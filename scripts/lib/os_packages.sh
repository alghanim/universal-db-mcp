#!/usr/bin/env bash
# Shared OS-package (dpkg) installer for the offline bundle scripts.
# Sourced by install_offline.sh and upgrade_offline.sh; provides:
#
#   udbmcp_install_os_packages <bundle-dir> <python-bin> [sudo-prefix]
#
# dpkg ONLY — apt is never invoked, so nothing here can reach a network or a
# vendor repository. Idempotent and VERSION-AWARE:
#   - a package already installed at exactly the bundled version is skipped;
#   - an older installed version is upgraded by dpkg -i;
#   - a NEWER installed version is left untouched (never silently downgraded);
#   - any other dpkg state (removed-but-not-purged "config-files",
#     half-installed, unpacked, half-configured, ...) triggers a (re)install,
#     because `dpkg -s` returns success for every one of those states.
# After every dpkg -i the resulting state is re-queried and must be exactly
# "installed", or the whole operation fails loudly.

# shellcheck shell=bash

# _udbmcp_dpkg_locks_held — true (rc 0) when dpkg's fcntl record locks are
# held by some other process RIGHT NOW. dpkg locks /var/lib/dpkg/lock-frontend
# and /var/lib/dpkg/lock with fcntl record locks (flock(2) would not see
# them), so each file is probed with a non-blocking fcntl exclusive lock that
# is released immediately. A missing/unopenable lock file is treated as free
# (dpkg creates them on demand); if python3 is unavailable the probe cannot
# run and the caller must assume "held" (defer) rather than risk the
# guaranteed "frontend lock" deadlock inside a maintainer script. Lock paths
# are overridable via UDBMCP_DPKG_LOCK_FILES (space-separated) for sandboxed
# tests; the default is exactly what dpkg uses on Ubuntu.
_udbmcp_dpkg_locks_held() {
  command -v python3 >/dev/null 2>&1 || return 0
  local lock_files="${UDBMCP_DPKG_LOCK_FILES:-/var/lib/dpkg/lock-frontend /var/lib/dpkg/lock}"
  if python3 -I -S - $lock_files 2>/dev/null <<'PYEOF'
import fcntl, sys
rc = 0
for path in sys.argv[1:]:
    try:
        fh = open(path, "r+")
    except OSError:
        continue  # absent: dpkg creates it on demand; nothing held on it
    try:
        fcntl.lockf(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.lockf(fh, fcntl.LOCK_UN)
    except OSError:
        rc = 1  # someone else holds this lock
    finally:
        fh.close()
sys.exit(rc)
PYEOF
  then
    return 1  # probe succeeded everywhere: locks are free
  fi
  return 0   # at least one lock is held (or the probe could not run)
}

udbmcp_install_os_packages() {
  local bundle="$1" py="$2" sudo_ok="${3:-}"
  local ospkg_dir="$bundle/os-packages"

  if [ -n "$sudo_ok" ]; then
    _udbmcp_rootrun() { "$sudo_ok" "$@"; }
  else
    _udbmcp_rootrun() { "$@"; }
  fi

  # The bundle may be a root-only staging copy (verify-then-use hardening in
  # the callers), so probe for .debs in the consuming (privileged) context.
  # `ls` of a directory prints bare entry names, which keeps the fallback
  # ordering below and the manifest `file` values comparable.
  if ! _udbmcp_rootrun ls -1 "$ospkg_dir" 2>/dev/null | grep -q '\.deb$'; then
    echo "==> no OS packages in bundle os-packages/ (skipping dpkg step)"
    return 0
  fi

  # --- dpkg critical section: DEFER, never nest dpkg --------------------------
  # Inside a dpkg maintainer script (deb postinst) the OUTER `dpkg -i` holds
  # the dpkg frontend/database locks for its whole run, so any nested `dpkg -i`
  # here always aborts with "dpkg frontend lock was locked by another
  # process". Skipping silently would hide the ODBC driver closure; failing
  # would abort the configure step for a condition that resolves itself once
  # dpkg exits. This branch is a fail-safe tripwire for that context: it is
  # normally unreachable for the .deb (packaging/deb/postinst defers the whole
  # dpkg-dependent install to its detached worker BEFORE install_offline.sh
  # ever runs), but any future maintainer-script caller lands here instead of
  # deadlocking. It triggers only when a maintainer-script context is combined
  # with dpkg's locks being genuinely held RIGHT NOW (the deb's deferred
  # worker inherits DPKG_MAINTSCRIPT_PACKAGE in its environment but runs AFTER
  # dpkg released the locks, so it correctly proceeds to install). The pending
  # state is recorded behind a root-owned marker under /run — NOT under the
  # udbmcp-owned /var/lib/universal-db-mcp, which the service account could
  # pre-create or remove — and the function returns success so the rest of the
  # trusted install (venv, smoke check) still completes; the marker stays
  # behind as a loud, inspectable record that the OS packages remain pending.
  # Outside a maintainer script the behavior is unchanged: dpkg runs directly.
  if { [ -n "${DPKG_MAINTSCRIPT_PACKAGE:-}" ] || [ -n "${DPKG_FRONTEND_LOCKED:-}" ]; } \
     && _udbmcp_dpkg_locks_held; then
    _defer_marker="${UDBMCP_OSPKG_DEFER_MARKER:-/run/universal-db-mcp/os-packages.pending}"
    if ! { mkdir -p "$(dirname "$_defer_marker")" 2>/dev/null && : > "$_defer_marker"; }; then
      echo "FAIL: cannot record deferred OS-package state at $_defer_marker;" >&2
      echo "      refusing to either nest 'dpkg -i' (dpkg locks held) or" >&2
      echo "      silently skip the bundle OS packages (fail closed)." >&2
      return 1
    fi
    echo "==> dpkg maintainer-script context with dpkg locks held: OS-package installation DEFERRED"
    echo "    (a nested 'dpkg -i' could never succeed against the outer dpkg's locks)."
    echo "    PENDING marker: $_defer_marker — install the bundle OS packages"
    echo "    once dpkg is idle by re-running the original installer with the"
    echo "    ORIGINAL bundle path (this staging copy is removed on exit),"
    echo "    e.g.: install_offline.sh <bundle-dir>  (dpkg only, no apt, no network)."
    return 0
  fi

  echo "==> installing OS packages from bundle os-packages/ (dpkg only, no apt, no network)"
  command -v dpkg >/dev/null 2>&1 || {
    echo "FAIL: dpkg not available; cannot install bundle OS packages" >&2
    return 1
  }
  # Privileged execution must actually work before the first package mutation;
  # a path-derived privilege decision used to be silently skipped here.
  _udbmcp_rootrun true 2>/dev/null || {
    echo "FAIL: privileged execution unavailable (run as root, or ensure sudo works);" >&2
    echo "      installing OS packages always requires root." >&2
    return 1
  }

  # Install in the manifest-declared dependency order (unixodbc stack before
  # msodbcsql18, whose postinst runs `odbcinst`). The manifest read runs in the
  # consuming context for the same staging reason as above.
  local order
  order="$(_udbmcp_rootrun "$py" -I -S - "$bundle/manifest.json" <<'PYEOF'
import json, sys
try:
    with open(sys.argv[1]) as fh:
        m = json.load(fh)
except FileNotFoundError:
    sys.exit(0)
for entry in (m.get("os_packages") or {}).get("packages", []):
    print(entry["file"])
PYEOF
)"
  if [ -z "$order" ]; then
    # Bundles without a manifest os_packages section: fall back to the same
    # tiers as the builder's OS_PACKAGE_INSTALL_ORDER (prepare_offline_bundle.py):
    # krb5/libltdl libs, then unixodbc-common + libodbc2/libodbcinst2, then the
    # unixodbc/odbcinst CLI packages that depend on those libs, and finally
    # msodbcsql18 (whose postinst runs `odbcinst`). Filename anchors use `_`
    # after the package name because that is dpkg's name_version separator.
    order="$(_udbmcp_rootrun ls -1 "$ospkg_dir" 2>/dev/null \
      | awk '/\.deb$/ {
          if (/^libkeyutils1_|^libkrb5support0_|^libk5crypto3_|^libkrb5-3_|^libltdl7_/) print "0 " $0
          else if (/^unixodbc-common_/) print "4 " $0
          else if (/^libodbc2_/) print "5 " $0
          else if (/^libodbcinst2_/) print "6 " $0
          else if (/^unixodbc_/) print "7 " $0
          else if (/^odbcinst_/) print "8 " $0
          else if (/^msodbcsql18_/) print "9 " $0
          else print "3 " $0
        }' \
      | sort -k1,1 -k2 | cut -d' ' -f2-)"
  fi

  local debfile deb pkg bver inst state iver
  while IFS= read -r debfile; do
    [ -n "$debfile" ] || continue
    deb="$ospkg_dir/$debfile"
    _udbmcp_rootrun test -f "$deb" || {
      echo "FAIL: manifest-listed OS package missing from bundle: $debfile" >&2
      return 1
    }
    pkg="$(_udbmcp_rootrun dpkg-deb -f "$deb" Package)"
    bver="$(_udbmcp_rootrun dpkg-deb -f "$deb" Version)"
    # ${db:Status-Status} is the single word dpkg -s hides: "installed" only
    # for genuinely configured packages, "config-files"/"half-installed"/
    # "unpacked"/... otherwise. Unknown to dpkg -> empty.
    inst="$(dpkg-query -W -f='${db:Status-Status} ${Version}' "$pkg" 2>/dev/null || true)"
    state="${inst%% *}"
    iver="${inst#* }"
    if [ -z "$inst" ]; then
      echo "    not present in the dpkg database, installing: $pkg $bver"
    elif [ "$state" = "installed" ] && [ "$iver" = "$bver" ]; then
      echo "    already installed at required version, skipping: $pkg $iver"
      continue
    elif [ "$state" = "installed" ] && dpkg --compare-versions "$iver" gt "$bver"; then
      echo "    WARNING: installed $pkg $iver is NEWER than bundled $bver; leaving untouched (no downgrade)" >&2
      continue
    elif [ "$state" = "installed" ]; then
      echo "    upgrading $pkg: $iver -> $bver"
    else
      echo "    dpkg state is '${state:-unknown}', not 'installed'; (re)installing: $pkg $bver"
    fi
    echo "    dpkg -i: $debfile"
    # dpkg alone never touches the network; a missing dependency aborts with
    # dpkg's own dependency error instead of being silently resolved by apt.
    # The assignments must reach dpkg itself: prefixed onto `sudo` they land in
    # sudo's own environment, which env_reset strips before exec'ing dpkg, so
    # msodbcsql18's postinst would never see ACCEPT_EULA and would abort.
    # `sudo env VAR=... dpkg ...` (and plain `env` when root) sets them in the
    # child environment dpkg actually runs in.
    _udbmcp_rootrun env ACCEPT_EULA=Y DEBIAN_FRONTEND=noninteractive dpkg -i "$deb" || {
      echo "FAIL: dpkg -i $debfile failed." >&2
      echo "      The bundle ships the full dependency closure in $ospkg_dir;" >&2
      echo "      check the ordering/manifest (os_packages.install_order)." >&2
      echo "      Missing base-OS libraries (e.g. libltdl7) must be provided" >&2
      echo "      by the administrator; apt is never used here." >&2
      return 1
    }
    # Fail loudly if dpkg left the package in any non-installed state (a
    # failed postinst leaves "half-configured" while dpkg -i still "succeeds"
    # from dpkg's point of view for that invocation).
    state="$(dpkg-query -W -f='${db:Status-Status}' "$pkg" 2>/dev/null || true)"
    if [ "$state" != "installed" ]; then
      echo "FAIL: $pkg is in dpkg state '${state:-unknown}' after dpkg -i (expected 'installed')." >&2
      return 1
    fi
  done < <(printf '%s\n' "$order")

  # The msodbcsql18 postinst registers the driver via odbcinst; verify and
  # register manually from the shipped odbcinst.ini if that did not happen.
  if command -v odbcinst >/dev/null 2>&1; then
    if odbcinst -q -d -n "ODBC Driver 18 for SQL Server" >/dev/null 2>&1; then
      echo "    ODBC driver registered: ODBC Driver 18 for SQL Server"
    elif _udbmcp_rootrun test -f /opt/microsoft/msodbcsql18/etc/odbcinst.ini; then
      echo "    registering ODBC driver from the shipped odbcinst.ini"
      _udbmcp_rootrun odbcinst -i -d -f /opt/microsoft/msodbcsql18/etc/odbcinst.ini
    fi
  fi
  return 0
}
