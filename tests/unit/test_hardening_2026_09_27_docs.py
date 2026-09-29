"""Docs stage of the 2026-09-27 production/security review.

The documents are part of the security posture: a runbook step that runs a
file from the stick before checking its signature, or a landing page that
promises more than the server does, is a defect like any other. These tests
pin the review's documentation fixes:

* F65: SECURITY.md exists, reports go through GitHub private vulnerability
  reporting only (no address to mail), and README.md and the site link it.
* F61: the project is Apache-2.0 as pyproject declares it; the README and the
  site footer say so, and no document still says there is no license.
* F14: the site runbook checks the stick's SHA256SUMS.sig with the host's own
  openssl before anything from the stick runs, and takes file names from the
  signed list rather than from globs.
* F80/F46: the Claude Code integration guide registers through
  configure-agents with the per-user config, and every registration shown in
  the docs starts the server with the same args configure-agents writes.
* F16/F01/F81: tools.md documents QUERY_ERROR and the masking limitation, and
  the landing page no longer says writes are impossible without a qualifier.

The integration review then checked these documents against the code again;
the next section pins what it found out of step: the mode the .deb's
conffile really has, Db2's explain-table writes, the upgrade's two doctor
runs outside -I, the anti-rollback gaps, and what an upgrading site meets.

The final round (2026-09-28) changed the code again and took the owner's
decisions of that day; the last section holds the ledger (§3f of
IMPLEMENTATION_STATUS.md) to the tree: the dummy tables, the verifier's
installed-manifest default, the container hosts' release record, the
maintainer identity without an address, the residuals that stay open, and
what only another host can verify. It also keeps every document off a
contact address, off the claims earlier reports withdrew, and on the
package copies bootstrap.sh checked for `dpkg -i`.

The review of that round's documents found claims wider than the code; the
fix-up section holds them to it: the listings that still name a view of
other sessions' SQL, the engines the EXPLAIN ANALYZE flag applies to, the
Db2 explain-table grants, a quick start whose bundle its installer can
verify, what doctor does not check, the MSI's downgrade rule and the one
test count the site and the ledger give.

The convergence wave (2026-09-29) fixed classes of defects and re-attacked
the result; its section holds the documents to what that changed: the view
and synonym listings that now leave out the views no statement may read, the
session settings each connector pins to the guard's reading, the refusals
the guard added, the audit's refusal coalescing and text budget, the
executor's server keys, the ordered release sticks, the private copies the
installers make, the macOS log files and the ledger's account of the wave.

The review of that stage's documents found claims wider than the code
again; the last section holds them to it: a bare PostgreSQL dictionary name
that no system-schema rule closes, what a client cancel changed, the
summaries an audit window can write, the Oracle literals the guard cannot
parse and the two database-link refusals, the Instant Client files a hard
link can still reach, the MSI's NT SERVICE names, the modes of the
installers' private copy, what the upgrade backs up at metadata.sqlite, the
ClickHouse settings config.example.yaml names and the site's test-count
date.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tomllib
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

import pytest

from universal_db_mcp.agents.core import SERVER_ARGS
from universal_db_mcp.config import ConnectionConfig, SecurityConfig
from universal_db_mcp.discovery.system_schemas import DATA_FREE_TABLES, SESSION_SQL_VIEWS
from universal_db_mcp.errors import ToolFailure
from universal_db_mcp.security.policy import EffectivePolicy
from universal_db_mcp.security.sql_guard import SqlGuard

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
SRC = ROOT / "src" / "universal_db_mcp"
SECURITY = ROOT / "SECURITY.md"
README = ROOT / "README.md"
PAGE = ROOT / "site" / "index.html"
RUNBOOK = DOCS / "site-upgrade-runbook.md"
LEDGER = ROOT / "IMPLEMENTATION_STATUS.md"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _bash_blocks(text: str) -> list[str]:
    return re.findall(r"```bash\n(.*?)```", text, flags=re.DOTALL)


def _project() -> dict[str, Any]:
    project = tomllib.loads(_read(ROOT / "pyproject.toml"))["project"]
    assert isinstance(project, dict)
    return project


def _pyproject_license() -> str:
    license_ = _project()["license"]
    assert isinstance(license_, str)
    return license_


# ---- F65: vulnerability disclosure ------------------------------------------

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")


def test_f65_security_md_has_a_reporting_section_and_no_email_address() -> None:
    text = _read(SECURITY)
    assert re.search(r"(?m)^#+\s*Reporting\b", text), "SECURITY.md needs a 'Reporting' section"
    assert "private vulnerability reporting" in text.lower()
    assert not _EMAIL.search(text), "reports go through GitHub private vulnerability reporting only"
    assert "mailto:" not in text.lower()
    # the parts the policy promises: supported versions and the air-gapped path
    assert re.search(r"(?m)^#+\s*Supported versions\b", text)
    assert "SHA256SUMS.sig" in text and "out of band" in text


def test_f65_readme_and_site_link_the_security_policy() -> None:
    assert "SECURITY.md" in _read(README)
    footer = re.search(r"<footer\b.*?</footer>", _read(PAGE), flags=re.DOTALL)
    assert footer is not None
    assert 'data-repo="SECURITY.md"' in footer.group(0)


# ---- F61: license -----------------------------------------------------------


def test_f61_readme_states_the_license_pyproject_declares() -> None:
    license_ = _pyproject_license()
    assert license_ == "Apache-2.0"
    section = re.search(r"(?ims)^#+\s*licen[cs]e\b(.*?)(?=^#+\s|\Z)", _read(README))
    assert section is not None, "README.md needs a License section"
    assert license_ in section.group(1)
    assert "Apache License" in _read(ROOT / "LICENSE") and (ROOT / "NOTICE").is_file()


def test_f61_site_footer_links_the_license() -> None:
    footer = re.search(r"<footer\b.*?</footer>", _read(PAGE), flags=re.DOTALL)
    assert footer is not None
    assert 'data-repo="LICENSE"' in footer.group(0)
    assert "Apache" in footer.group(0)


_NO_LICENSE = re.compile(
    r"\bno licen[cs]e\b|\bno LICENSE file\b|\bunlicensed\b|\bnot (?:yet )?(?:licensed|open[- ]source)\b"
    r"|\bproprietary licen[cs]e\b|\blicen[cs]e[^.\n]{0,20}\bproprietary\b",
    re.IGNORECASE,
)


def _current_docs() -> list[Path]:
    """The documents that describe the project as it is now (the review
    archives in docs/*.json are historical records and stay as written)."""
    paths = [README, SECURITY, ROOT / "IMPLEMENTATION_STATUS.md", PAGE, ROOT / "config.example.yaml"]
    paths += sorted(DOCS.glob("*.md"))
    return [p for p in paths if p.is_file()]


def test_f61_no_document_says_the_project_has_no_license() -> None:
    offenders = {
        str(path.relative_to(ROOT)): match.group(0)
        for path in _current_docs()
        if (match := _NO_LICENSE.search(_read(path)))
    }
    assert not offenders, offenders


# ---- F14: the runbook checks the stick before running anything from it ------


def test_f14_runbook_verifies_the_stick_signature_before_bootstrap_and_dpkg() -> None:
    blocks = _bash_blocks(_read(RUNBOOK))

    def first(predicate: object) -> int | None:
        assert callable(predicate)
        return next((i for i, block in enumerate(blocks) if predicate(block)), None)

    verify = first(lambda b: "/usr/bin/openssl pkeyutl -verify" in b and "SHA256SUMS.sig" in b)
    bootstrap = first(lambda b: re.search(r"sudo bash \S*bootstrap\.sh", b))
    dpkg = first(lambda b: "dpkg -i" in b)
    assert verify is not None, "step 0 must check SHA256SUMS.sig with the host's /usr/bin/openssl"
    assert bootstrap is not None and dpkg is not None
    assert verify < bootstrap and verify < dpkg
    # an upgrade runs the INSTALLED bootstrap against the new stick
    assert "sudo bash /usr/local/lib/udbmcp-trust/bootstrap.sh --stick" in blocks[bootstrap]


def test_f14_runbook_takes_file_names_from_the_signed_list_not_globs() -> None:
    text = _read(RUNBOOK)
    for glob in ('ls "$STICK"/universal-db-mcp_', "libaio1t64_*.deb", "unzip_*.deb", "usb-ubuntu-*/universal"):
        assert glob not in text, glob
    assert "libaio1t64_0.3.113-6build1.1_amd64.deb" in text
    assert "unzip_6.0-28ubuntu4.1_amd64.deb" in text
    # sha256sum -c does not see an added file; the runbook must not imply it does
    assert "not on the signed list" in text or "not on its signed SHA256SUMS" in text
    # the fingerprint is compared with the out-of-band value, not the stick's own file
    assert 'cat "$STICK/RELEASE-KEY-FINGERPRINT.txt"' not in text


def test_f78_runbook_writes_the_site_check_report_into_a_private_directory() -> None:
    text = _read(RUNBOOK)
    assert "--out /tmp/" not in text
    assert "mktemp -d" in text


# ---- F80 / F46: agent registration ------------------------------------------


def test_f80_claude_code_guide_registers_through_configure_agents() -> None:
    text = _read(DOCS / "claude-code-integration.md")
    assert "configure-agents" in text and "~/.claude.json" in text
    assert "~/.universal-db-mcp/config.yaml" in text
    for block in re.findall(r"```json\n(.*?)```", text, flags=re.DOTALL):
        assert "/etc/universal-db-mcp/config.yaml" not in block, "a stdio registration cannot read the system config"
    assert "~/.mcp.json" not in text


def test_f46_every_registration_in_the_docs_starts_the_server_isolated() -> None:
    shown = 0
    for path in [README, *sorted(DOCS.glob("*.md"))]:
        text = _read(path)
        for block in re.findall(r"```json\n(.*?)```", text, flags=re.DOTALL):
            if '"mcpServers"' not in block:
                continue  # a response fragment, not a registration
            for server in json.loads(block)["mcpServers"].values():
                if server.get("type", "stdio") == "stdio":
                    shown += 1
                    assert tuple(server["args"]) == SERVER_ARGS, path.name
        for args in re.findall(r"args: \[(.*?)\]", text):
            if "universal_db_mcp" in args:
                shown += 1
                assert tuple(a.strip().strip("'\"") for a in args.split(",")) == SERVER_ARGS, path.name
    assert shown >= 3


# ---- F16 / F01 / F81: what the docs and the site promise ---------------------


def test_f16_f01_tools_md_documents_query_error_and_the_masking_limit() -> None:
    text = _read(DOCS / "tools.md")
    assert "| `QUERY_ERROR` |" in text
    assert "<redacted>" in text
    limitation = text[text.index("**Limitation (owner decision):**") :]
    assert "WHERE" in limitation and "column-level grants" in limitation


def test_f81_the_landing_page_qualifies_the_no_writes_claim() -> None:
    page = _read(PAGE)
    assert "Writes are impossible" not in page
    assert "Writes aren't discouraged" not in page
    assert "Writes through it" in page
    assert "SELECT-only login" in page


def test_msi_docs_name_the_admin_only_key_location() -> None:
    text = _read(DOCS / "offline-deployment.md")
    assert 'setx /M UDBMCP_RELEASE_PUBKEY "C:\\Program Files\\udbmcp-trust\\keys\\udbmcp-release.pub.pem"' in text
    assert 'setx /M UDBMCP_RELEASE_PUBKEY "C:\\ProgramData' not in text
    assert "only if absent or empty, never clobbered" not in text


# ---- integration review: claims the docs made that the code does not keep ----


def _flat(path: Path) -> str:
    """The document with every run of whitespace, line breaks included, as one space."""
    return " ".join(_read(path).split())


def _deb_conffile_mode() -> str:
    """The mode build_deb.sh stages /etc/universal-db-mcp/config.yaml with."""
    match = re.search(
        r'install -m (\d+) "\$CONFIG_TEMPLATE" "\$DEBROOT/etc/universal-db-mcp/config\.yaml"',
        _read(ROOT / "scripts" / "package" / "build_deb.sh"),
    )
    assert match is not None, "build_deb.sh no longer stages the conffile the way this test reads it"
    return match.group(1)


_CONFIG_TO_SERVICE = (
    "sudo chown root:udbmcp /etc/universal-db-mcp/config.yaml && sudo chmod 640 /etc/universal-db-mcp/config.yaml"
)


def test_f80_the_docs_state_the_deb_conffile_mode_configure_agents_meets() -> None:
    mode = _deb_conffile_mode()
    guide = _flat(DOCS / "claude-code-integration.md")
    assert "`.deb` or `.pkg`, the system config belongs to the service account (mode 0640" not in guide
    if int(mode, 8) & 0o004:
        # readable by every user, so configure-agents registers it; the guide says so and gives the fix
        assert f"`root:root` {mode}" in guide
        assert _CONFIG_TO_SERVICE in guide
        assert "cannot read on a packaged host" not in _flat(DOCS / "mock-environment.md")
        assert "`.deb`" in _flat(DOCS / "mock-environment.md")
    readme = _flat(README)
    assert "if you want a config other than the per-user default" not in readme
    assert "when your user can read it" in readme


_DB2_EXPLAIN_GRANTS = "INSERT, SELECT and DELETE"


def test_f81_the_site_and_readme_name_the_explain_writes() -> None:
    db2 = _read(ROOT / "src" / "universal_db_mcp" / "connectors" / "db2.py")
    assert "EXPLAIN PLAN SET QUERYNO" in db2 and "DELETE FROM {q}.EXPLAIN_INSTANCE" in db2
    page = _flat(PAGE)
    assert "no tool issues writes" not in page
    assert "They're impossible" not in page
    faq = re.search(r"<summary>Can it write to my database, even by accident\?</summary><p>(.*?)</p>", page)
    assert faq is not None
    for needle in ("explain tables", "INSERT", "DELETE", "PLAN_TABLE"):
        assert needle in faq.group(1), needle
    needs = re.search(r"<summary>What do I need on the database side\?</summary><p>(.*?)</p>", page)
    # the connector reads EXPLAIN_STATEMENT and EXPLAIN_OPERATOR back between the two
    assert needs is not None and _DB2_EXPLAIN_GRANTS in needs.group(1)
    # the stick is first checked by the host's openssl, not by tools an earlier release installed
    assert "using tools installed by an earlier release" not in page
    assert "openssl" in page
    readme = _flat(README)
    assert "explain tables" in readme and _DB2_EXPLAIN_GRANTS in readme
    assert _DB2_EXPLAIN_GRANTS in _flat(DOCS / "security.md")


def test_the_isolation_claims_name_the_upgrade_doctor_runs_outside_it() -> None:
    script = _read(ROOT / "scripts" / "upgrade_offline.sh")
    if re.search(r'/bin/python" -m universal_db_mcp doctor', script):
        for name in ("offline-deployment.md", "offline-upgrade-rollback.md"):
            assert "`doctor` checks without `-I`" in _flat(DOCS / name), name


def test_f65_security_md_names_the_anti_rollback_gaps() -> None:
    text = _read(SECURITY)
    section = re.search(r"(?ms)^## Supported versions\n(.*?)(?=^## )", text)
    assert section is not None
    flat = " ".join(section.group(1).split())
    assert "release_seq" in flat
    assert "`.pkg`" in flat and "container" in flat
    assert "so an old signed build cannot roll a fixed site back by accident" not in flat
    # a first install, and the first upgrade to a release with bootstrap.sh, check with the host's openssl
    assert "/usr/bin/openssl" in " ".join(text.split())


def test_the_runbook_lists_the_upgrade_visible_changes() -> None:
    text = _read(RUNBOOK)
    section = " ".join(text[text.index("## Behaviour changes in this release") : text.index("## Rollback")].split())
    ceiling = re.search(
        r"^_EXPLAIN_MAX_ROWS_TO_READ = (\d+)",
        _read(ROOT / "src" / "universal_db_mcp" / "connectors" / "clickhouse.py"),
        flags=re.MULTILINE,
    )
    assert ceiling is not None
    assert "_APPLICATION_PATH_KEYS" in _read(ROOT / "src" / "universal_db_mcp" / "config.py")
    assert "against the config file's directory" in section
    assert "`allow_explain_analyze: true`" in section
    assert f"{ceiling.group(1)}-row" in section
    assert "`db_list_databases`" in section


def test_the_runbook_says_where_the_docs_it_cites_live() -> None:
    text = _read(RUNBOOK)
    cited = set(re.findall(r"`docs/([a-z0-9-]+\.md)`", text))
    assert cited
    for name in cited:
        assert (DOCS / name).is_file(), name
    # the stick carries this runbook only; the bundle (in the package) carries docs/
    usb = _read(ROOT / "scripts" / "package" / "release_usb.sh")
    assert "cp docs/site-upgrade-runbook.md" in usb
    if not re.search(r"^cp .*\bdocs/(?!site-upgrade-runbook\.md)", usb, flags=re.MULTILINE):
        assert 'out / "docs" / doc.name' in _read(ROOT / "scripts" / "prepare_offline_bundle.py")
        assert "/usr/share/universal-db-mcp/bundle/docs/" in text


def test_readme_airgapped_quick_start_installs_the_config_before_doctor_reads_it() -> None:
    installer = _read(ROOT / "scripts" / "install_offline.sh")
    assert "config-templates/config.yaml to /etc/universal-db-mcp/config.yaml" in installer  # a next step, not done
    block = next(b for b in _bash_blocks(_read(README)) if "install_offline.sh" in b)
    placed = block.find("config-templates/config.yaml /etc/universal-db-mcp/config.yaml")
    doctor = block.find("doctor --config /etc/universal-db-mcp/config.yaml")
    assert 0 <= placed < doctor


def test_clickhouse_provisioning_states_the_readonly_trade_off() -> None:
    text = _read(DOCS / "driver-matrix.md")
    start = text.index("-- ClickHouse")
    block = " ".join(text[start : text.index("```", start)].split())
    assert "readonly = 1" in block and "readonly = 2" in block
    for needle in ("skipped", "max_execution_time", "planning ceiling", "MAX"):
        assert needle in block, needle


# ---- final round (2026-09-28): the ledger against the code -------------------


def _ledger_part(start: str, end: str) -> str:
    """The flattened ledger from ``start`` up to the next ``end`` after it."""
    ledger = _flat(LEDGER)
    at = ledger.index(start)
    return ledger[at : ledger.index(end, at + len(start))]


def _residuals() -> str:
    return _ledger_part("**Residuals that remain open**", "**Not verified on this Mac**")


def test_the_ledger_says_what_older_packages_and_container_hosts_still_refuse() -> None:
    ledger = _flat(LEDGER)
    assert "`.pkg` and MSI packages built before this release cannot refuse a downgrade" not in ledger
    gaps = ledger[ledger.index("**Anti-rollback gaps:**") :]
    gaps = gaps[: gaps.index("- **", 5)]
    record = re.search(
        r'^RELEASE_RECORD="\$\{UDBMCP_RELEASE_RECORD:-([^}]+)\}"',
        _read(ROOT / "scripts" / "load_images_offline.sh"),
        flags=re.MULTILINE,
    )
    if record is not None:  # container hosts keep a release record (owner decision 2026-09-28)
        assert "container mode has no installed-release record" not in ledger
        assert f"`{record.group(1)}`" in gaps and "container" in gaps
    if "--no-installed-manifest" in _read(ROOT / "scripts" / "verify_bundle.py"):
        # an older .pkg or .msi calls the site's trusted verifier without
        # --installed-manifest; the verifier's own default refuses it, once
        # the trust directory holds this release's copy
        assert "this release's `verify_bundle.py`" in gaps and "trust directory" in gaps
    if "release_seq" in _read(ROOT / "scripts" / "package" / "build_msi.sh"):
        assert "every 0.1.x build is ProductVersion 0.1.0" not in ledger
        assert "ProductVersion" in gaps


def test_the_ledger_records_the_2026_09_28_owner_decisions_as_the_tree_has_them() -> None:
    decisions = _ledger_part("**Owner decisions (2026-09-28, binding):**", "**What was fixed**")
    assert ("SYS", "DUAL") in DATA_FREE_TABLES["oracle"] and ("SYSIBM", "SYSDUMMY4") in DATA_FREE_TABLES["db2"]
    assert "`DUAL`" in decisions and "`SYSIBM.SYSDUMMY1`" in decisions
    assert "--no-installed-manifest" in _read(ROOT / "scripts" / "verify_bundle.py")
    assert "`--no-installed-manifest`" in decisions
    assert "`/var/lib/universal-db-mcp/release.json`" in decisions
    # the maintainer identity carries no address; Debian's required one is reserved and non-routable
    project = _project()
    assert project["authors"] == [{"name": "universal-db-mcp maintainers"}] and "urls" not in project
    control = "Maintainer: universal-db-mcp maintainers <maintainers@universal-db-mcp.invalid>"
    assert control in _read(ROOT / "packaging" / "deb" / "control")
    assert control in _read(ROOT / "scripts" / "package" / "build_deb.sh")
    assert 'Manufacturer="universal-db-mcp maintainers"' in _read(ROOT / "packaging" / "msi" / "udbmcp.wxs")
    assert "`universal-db-mcp maintainers`" in decisions
    assert "`maintainers@universal-db-mcp.invalid`" in decisions and "repository URL" in decisions


_RESERVED_MAIL_DOMAINS = ("universal-db-mcp.invalid", "example.com", "example.org", "example.net")


def test_no_document_publishes_a_contact_address() -> None:
    """Owner decision 2026-09-28: 'universal-db-mcp maintainers', no address;
    reports go through GitHub private vulnerability reporting only."""
    offenders = {
        str(path.relative_to(ROOT)): found
        for path in _current_docs()
        if (found := [m for m in _EMAIL.findall(_read(path)) if m.split("@")[1] not in _RESERVED_MAIL_DOMAINS])
    }
    assert not offenders, offenders


def _withdrawn_claims() -> dict[str, str]:
    """Text earlier reports gave the docs that the tree does not keep, with
    why; each applies while the code still says otherwise."""
    claims = {
        # SQL Server reads @1x as one variable and sqlglot splits nothing; #1x
        # is refused as unparsable, not as a fused literal (only $1e5 is new)
        "`@1x`": "SELECT @1x is still accepted",
        "`#1x`": "#1x is refused as unparsable, not as a fused literal",
    }
    if not any("policy-disabled" in _read(path) for path in SRC.rglob("*.py")):
        claims["policy-disabled"] = "EXPLAIN ANALYZE is never run; the connectors say it is not supported"
    if "UDBMCP_RELEASE_RECORD" in _read(ROOT / "scripts" / "load_images_offline.sh"):
        claims["container mode has no installed-release record"] = "the loader keeps a release record"
    return claims


def test_no_document_repeats_a_withdrawn_claim() -> None:
    claims = _withdrawn_claims()
    offenders = {
        f"{path.relative_to(ROOT)}: {claim}": why
        for path in _current_docs()
        for claim, why in claims.items()
        if claim in _flat(path)
    }
    assert not offenders, offenders


def test_the_docs_install_the_packages_bootstrap_checked() -> None:
    """bootstrap.sh copies the stick's .deb files into a root-only cache and
    checks the copies again; dpkg -i reads a package again and runs its
    preinst as root, so the docs install those copies, never the stick's."""
    cache = re.search(
        r'^DEB_DIR="\$ROOT(/[^"]+)"$',
        _read(ROOT / "packaging" / "trust-bootstrap-linux" / "bootstrap.sh"),
        flags=re.MULTILINE,
    )
    assert cache is not None, "bootstrap.sh no longer names its package cache the way this test reads it"
    for path in (RUNBOOK, DOCS / "offline-deployment.md", DOCS / "oracle-connect-modes.md"):
        text = _flat(path)
        assert cache.group(1) in text, path.name
        for from_stick in ("dpkg -i <stick>", 'dpkg -i "$STICK', "dpkg -i libaio1t64_", "dpkg -i unzip_"):
            assert from_stick not in text, (path.name, from_stick)
    for name in ("DEB", "C"):  # the package, and the Oracle step's folder of copies
        assigned = re.findall(rf'(?:^|[\s;(]){name}="?([^"\s;]+)', _read(RUNBOOK), flags=re.MULTILINE)
        assert assigned and all(value.startswith(cache.group(1)) for value in assigned), (name, assigned)


def test_the_ledger_names_the_final_round_guard_rules() -> None:
    fixed = _ledger_part("**What was fixed**", "**Residuals that remain open**")
    assert SESSION_SQL_VIEWS and "`SESSION_SQL_VIEWS`" in fixed
    assert "`SYS.DUAL`" in fixed and "`SYSIBM.SYSDUMMY1`" in fixed
    server = _read(SRC / "server.py")
    if "analyze=true is not supported by db_explain" in server:
        # the flag now only picks the refusal; the P2 pass of §1c said ANALYZE was still gated by it
        assert "`allow_explain_analyze`" in fixed and "VALIDATION_ERROR" in fixed
        assert "(ANALYZE/WAL still gated)" not in _flat(LEDGER)
    guard = _read(SRC / "security" / "sql_guard.py")
    if "_VALUE_PARAMETERS" in guard:  # a value after IN names nothing and stays allowed
        assert "placeholders and constants after `IN`" in fixed
    if "def _clickhouse_cte_refs" in guard:
        assert "not CTE-scope-aware (every server statement path compensates)" not in _flat(LEDGER)


def test_the_ledger_points_at_every_hardening_test_module() -> None:
    named = re.findall(r"`(?:tests/unit/)?(test_hardening_[\w*]+\.py)`", _read(LEDGER))
    for path in sorted((ROOT / "tests" / "unit").glob("test_hardening_2026_09_2*.py")):
        assert any(fnmatch(path.name, pattern) for pattern in named), path.name


def test_the_ledger_keeps_the_oracle_hung_listener_open() -> None:
    oracle = _read(SRC / "connectors" / "oracle.py")
    if "tcp_connect_timeout" in oracle and "connect_async" not in oracle:
        # python-oracledb bounds the TCP connect only; the handshake to a
        # listener that never answers is bounded by the executor alone
        residuals = _residuals()
        assert "F37" in residuals and "`tcp_connect_timeout`" in residuals


def test_the_ledger_states_the_sqlite_truncated_flag_as_the_connector_sets_it() -> None:
    sqlite = _read(SRC / "connectors" / "sqlite.py")
    if re.search(r"^\s*truncated=truncated,$", sqlite, flags=re.MULTILINE):
        # a cell cut to max_cell_bytes is a warning there; the other engines set truncated
        assert "cut to `max_cell_bytes` is reported by its warning only" in _residuals()


def test_the_ledger_names_what_only_another_host_can_verify() -> None:
    part = _ledger_part("**Not verified on this Mac**", "**Owner actions:**")
    for needle in ("**Windows:**", "**GitHub Actions:**", "**Apple signing:**", "**The Ubuntu site:**"):
        assert needle in part, needle
    if "CommitReleaseRecordCA" in _read(ROOT / "packaging" / "msi" / "udbmcp.wxs"):
        assert "`CommitReleaseRecordCA`" in part
    hygiene = _read(ROOT / "tests" / "unit" / "test_hardening_2026_09_27_ci_hygiene.py")
    if "def test_ci_runs_the_msi_custom_action_tests_under_pwsh" in hygiene:
        assert "pwsh" in part


def test_the_ledger_owner_actions_are_what_is_left() -> None:
    actions = _ledger_part("**Owner actions:**", "**Test status after this review:**")
    for needle in ("Git history and authorship", "release key", "private vulnerability reporting"):
        assert needle in actions, needle
    project = _project()
    if project["authors"] == [{"name": "universal-db-mcp maintainers"}]:
        assert "pick one maintainer identity" not in actions
    if "urls" not in project:
        assert "repository URL" in actions
    # decided 2026-09-28: redaction stays, and ClickHouse memory is the account profile's
    assert "identifier redaction" not in actions and "ClickHouse memory ceiling" not in actions


# ---- docs fix-up (2026-09-28): the final review's documents against the code --


def _scope_listing_source() -> str:
    """server._scope_listing, the policy scope of db_list_views,
    db_list_synonyms and db_list_routines."""
    match = re.search(r"^def _scope_listing\(.*?(?=^\S)", _read(SRC / "server.py"), flags=re.MULTILINE | re.DOTALL)
    assert match is not None, "server.py no longer defines _scope_listing the way this test reads it"
    return match.group(0)


_EVERY_LISTING = re.compile(
    r"left out of every listing|Views of other sessions' SQL are never listed(?! by)"
    r"|catalog listings of every engine honour it|governs every engine's catalog listing"
)


def test_no_document_says_every_listing_leaves_out_what_db_list_views_names() -> None:
    """Without an allowlist the view, synonym and routine listings hold the
    connector's catalog, dictionaries included, and under one they keep the
    opened system schemas (_scope_listing filters by schema only): PostgreSQL
    lists pg_catalog.pg_tables and pg_roles, Oracle the PUBLIC synonym
    ALL_USERS (live on the fixtures). The connectors now drop the views no
    statement may read from those listings (the convergence section below),
    but not every listing of every engine asks is_session_sql_view."""
    scope = _scope_listing_source()
    if "is_session_sql_view" in scope or "_never_listed" in scope or "not policy.allowed_schemas" not in scope:
        return  # the listings drop them now, or filter without an allowlist too
    offenders = {
        str(path.relative_to(ROOT)): found.group(0)
        for path in _current_docs()
        if (found := _EVERY_LISTING.search(_flat(path)))
    }
    assert not offenders, offenders
    security = _flat(DOCS / "security.md")
    sessions = security[security.index("**Views of other sessions' SQL.**") :]
    sessions = sessions[: sessions.index(" - **")]
    assert "`db_list_views`" in sessions and "`db_list_synonyms`" in sessions
    synonyms = next(line for line in _read(DOCS / "tools.md").splitlines() if line.startswith("| `db_list_synonyms`"))
    assert "PUBLIC" in synonyms and "allowlist" in synonyms
    residuals = _residuals()
    assert "`db_list_views`" in residuals and "`db_list_synonyms`" in residuals


_NAMESAKES_HIDDEN = re.compile(
    r"other spellings are left out of the listings|other spellings are hidden and refused"
    r"|and hidden from the listings"
)


def test_no_document_says_the_view_listings_hide_a_schema_namesake() -> None:
    """Under allowed_schemas: [ocean], _scope_listing keeps the views of a
    schema "Ocean" too (schema_allowed ignores case); only db_list_schemas and
    the table listing drop the spellings the policy does not admit."""
    scope = _scope_listing_source()
    if "shadowed" in scope or "schema_allowed" not in scope:
        return  # the view, synonym and routine listings drop namesakes now
    offenders = {
        str(path.relative_to(ROOT)): found.group(0)
        for path in _current_docs()
        if (found := _NAMESAKES_HIDDEN.search(_flat(path)))
    }
    assert not offenders, offenders
    security = _flat(DOCS / "security.md")
    namesakes = security[security.index("**Schema allowlist.**") : security.index("**System schemas.**")]
    assert "`db_list_views`" in namesakes and "`db_list_synonyms`" in namesakes
    assert "namesake" in _residuals()


def _explain_guard(engine: str, allow_explain_analyze: bool) -> SqlGuard:
    body: dict[str, Any] = {"type": engine, "host": "h", "database": "d", "username_env": "U"}
    policy = EffectivePolicy.build(
        SecurityConfig(allow_explain_analyze=allow_explain_analyze),
        type("R", (), {"config": ConnectionConfig.model_validate(body), "name": "c"})(),
    )
    return SqlGuard(engine, policy, None)


def test_the_docs_scope_the_explain_analyze_flag_to_the_engines_it_decides() -> None:
    """analyze=true, and ANALYZE written in a PostgreSQL, MySQL, ClickHouse or
    Db2 statement, is POLICY_VIOLATION or VALIDATION_ERROR by the flag;
    Oracle and SQL Server have no ANALYZE form and refuse it either way."""
    for engine in ("oracle", "mssql"):
        for allow in (False, True):
            with pytest.raises(ToolFailure) as refused:
                _explain_guard(engine, allow).validate_explain("EXPLAIN ANALYZE SELECT 1 FROM t")
            if not str(refused.value).startswith("POLICY_VIOLATION: "):
                return  # the flag decides there too; the unqualified sentence is true
    for path in (README, DOCS / "security.md", DOCS / "tools.md", LEDGER):
        text = _flat(path)
        for said in re.finditer(r"only (?:picks|chooses) the refusal", text):
            assert "Oracle and SQL Server" in text[said.start() - 600 : said.end() + 600], path.name


def test_every_document_gives_the_db2_explain_grants_the_connector_uses() -> None:
    db2 = _read(SRC / "connectors" / "db2.py")
    assert "EXPLAIN PLAN SET QUERYNO" in db2 and ".EXPLAIN_STATEMENT" in db2 and "DELETE FROM" in db2
    offenders = [str(path.relative_to(ROOT)) for path in _current_docs() if "INSERT and DELETE" in _flat(path)]
    assert not offenders, offenders
    for path in (ROOT / "config.example.yaml", DOCS / "tools.md", RUNBOOK, DOCS / "driver-matrix.md"):
        assert _DB2_EXPLAIN_GRANTS in _flat(path).replace(" # ", " "), path.name


def test_readme_quick_start_signs_the_bundle_its_installer_verifies() -> None:
    """install_offline.sh refuses a bundle without SIGNATURE when a key is
    given, and prepare_offline_bundle.py signs only with --signing-key."""
    assert "--signing-key" in _read(ROOT / "scripts" / "prepare_offline_bundle.py")
    block = next(b for b in _bash_blocks(_read(README)) if "install_offline.sh" in b)
    assert "UDBMCP_RELEASE_PUBKEY=" in block
    staging = block[block.index("prepare_offline_bundle.py") : block.index("install_offline.sh")]
    assert "--signing-key" in staging
    assert "out of band" in _flat(README)


def test_the_readme_gives_the_msi_downgrade_rule_windows_installer_keeps() -> None:
    wxs = _read(ROOT / "packaging" / "msi" / "udbmcp.wxs")
    if "<MajorUpgrade" in wxs and "AllowDowngrades" not in wxs:
        # MajorUpgrade refuses any older MSI over a newer install, whatever the property says
        readme = _flat(README)
        assert "for the `.deb` and the `.msi`" not in readme
        assert "after uninstalling" in readme
        runbook = _flat(RUNBOOK)
        assert "on Windows `UDBMCP_ALLOW_DOWNGRADE=1` for one `msiexec` run (see" not in runbook


def test_the_runbook_says_doctor_does_not_check_the_bearer_token_length() -> None:
    if "_MIN_BEARER_TOKEN_CHARS" in _read(SRC / "diagnostics" / "doctor.py"):
        return  # doctor checks it now
    assert "_MIN_BEARER_TOKEN_CHARS = 32" in _read(SRC / "__main__.py")
    text = _read(RUNBOOK)
    at = text.index("- **Config that no longer loads.**")
    section = text[at : text.index("\n- **", at)]
    checked = section[: section.index("\n\n")] if "\n\n" in section else section
    assert "bearer token" not in checked, "doctor checks the token file's presence and mode, not its length"
    assert "bearer token" in section and "wc -c" in section


def test_the_ledger_keeps_the_instant_client_zip_residual_current() -> None:
    if "/var/cache/udbmcp-trust/oracle-instantclient" in _read(RUNBOOK):
        assert "Instant Client zip is still read from the stick" not in _residuals()


def test_the_site_and_the_ledger_give_one_test_count() -> None:
    status = re.search(r"\*\*Test status after this review:\*\* `(\d+) passed, (\d+) skipped", _read(LEDGER))
    assert status is not None
    passed = int(status.group(1))
    page = _read(PAGE)
    assert f'data-count="{passed}" data-sep="1">{passed:,}</b>' in page
    faq = re.search(r"<summary>Is it production-ready\?</summary><p>(.*?)</p>", page)
    assert faq is not None and f"{passed:,} automated tests" in faq.group(1)
    assert not re.search(r"\b\d,\d{3} automated tests\b", page.replace(f"{passed:,} automated tests", ""))


# ---- convergence wave (2026-09-29): this wave's code against the documents ---


def _connector(engine: str) -> str:
    return _read(SRC / "connectors" / f"{engine}.py")


def _method(source: str, name: str) -> str:
    """The body of the method ``name`` in a connector's ``source``, up to the next method."""
    match = re.search(rf"\n    def {name}\(.*?(?=\n    (?:@|def ))", source, flags=re.DOTALL)
    assert match is not None, f"no method {name} the way this test reads it"
    return match.group(0)


_NAMES_A_REFUSED_VIEW = re.compile(
    r"can still name (?:one|it|them|such a view)|PUBLIC synonym `V\$SQL`|\(`V\$SQL`\) included"
    r"|`pg_catalog\.pg_stat_activity` among them|the PUBLIC `V\$SQL` and `V\$SESSION` among them"
)


def test_no_document_says_a_view_listing_names_a_view_no_statement_may_read() -> None:
    """PostgreSQL's, Oracle's and Db2's view listings and Oracle's and Db2's
    synonym listings leave out every view is_session_sql_view matches (other
    sessions' SQL, column statistics, stored credentials), and a synonym or
    alias whose chain reaches one. Live on the fixtures (2026-09-29, no
    allowlist): mock_pg's db_list_views no longer names pg_stat_activity or
    pg_stats, mock_oracle's db_list_synonyms no longer names PUBLIC V$SQL or
    ALL_TAB_HISTOGRAMS, mock_db2's db_list_views no longer names
    SYSIBMADM.MON_CURRENT_SQL or SYSCAT.COLDIST; pg_roles, ALL_USERS and
    SYSCAT.TABLES are still listed."""
    filtered = {
        ("postgres", "list_views"): "is_session_sql_view",
        ("oracle", "list_views"): "is_session_sql_view",
        ("db2", "list_views"): "is_session_sql_view",
        ("oracle", "list_synonyms"): "synonym_names_refused_view",
        ("db2", "list_synonyms"): "synonym_names_refused_view",
    }
    if not all(check in _method(_connector(engine), name) for (engine, name), check in filtered.items()):
        return  # a listing still names them; the fix-up section's wording applies
    offenders = {
        str(path.relative_to(ROOT)): found.group(0)
        for path in _current_docs()
        if (found := _NAMES_A_REFUSED_VIEW.search(_flat(path)))
    }
    assert not offenders, offenders
    views = next(line for line in _read(DOCS / "tools.md").splitlines() if line.startswith("| `db_list_views`"))
    assert "other sessions' SQL" in views and "column statistics" in views and "stored credentials" in views
    # the other dictionary objects are still listed without an allowlist: a residual
    residuals = _residuals()
    assert "`db_list_routines`" in residuals and "`pg_roles`" in residuals and "`ALL_USERS`" in residuals


def test_session_safety_names_every_setting_a_connector_holds_for_the_guard() -> None:
    """Each connector holds the settings that decide how its server reads a
    statement at the values the SQL guard parsed under, and refuses the
    connection when it cannot: '... the server would read statements
    differently from the SQL guard that checked them, so the connection is
    refused'."""
    if "def _reading_required" not in _read(SRC / "connectors" / "base.py"):
        return
    from universal_db_mcp.connectors import clickhouse, mysql

    held: dict[str, tuple[str, ...]] = {
        "mysql": ("sql_mode", "utf8mb4", *mysql._MYSQL_LEXING_MODES),
        "postgres": ("standard_conforming_strings", "backslash_quote", "client_encoding"),
        "mssql": ("QUOTED_IDENTIFIER",),
        "db2": ("SQL_COMPAT",),
        "clickhouse": tuple(clickhouse._CH_READING_SETTINGS),
    }
    doc = _flat(DOCS / "session-safety.md")
    for engine, names in held.items():
        source = _connector(engine)
        assert "self._reading_required(" in source, engine
        for name in names:
            # named in the connector, and in a code span of the page
            assert name in source and re.search(rf"`[^`]*\b{re.escape(name)}\b[^`]*`", doc), (engine, name)
    refusal = "the server would read statements differently from the SQL guard that checked them"
    for path in (DOCS / "session-safety.md", DOCS / "troubleshooting.md", RUNBOOK):
        assert refusal in _flat(path), path.name
    assert "sql_compat (no Netezza mode before Db2 11.1)" in doc


def test_security_md_names_the_views_that_hand_back_values_or_credentials() -> None:
    """Column statistics and stored credentials are refused whatever
    allowed_system_schemas opens, and the column catalogs that carry low and
    high values only without those columns; every name the page gives as an
    example is one the code's patterns match."""
    from universal_db_mcp.discovery import system_schemas

    text = _flat(DOCS / "security.md")
    statistics = getattr(system_schemas, "COLUMN_STATISTICS_VIEWS", None)
    if statistics:
        assert "holds column statistics" in text
        for engine, schema, name in (
            ("mysql", "information_schema", "COLUMN_STATISTICS"),
            ("postgres", "pg_catalog", "pg_stats"),
            ("oracle", "SYS", "ALL_TAB_HISTOGRAMS"),
            ("db2", "SYSCAT", "COLDIST"),
            ("mssql", "sys", "dm_db_stats_histogram"),
        ):
            assert system_schemas.is_column_statistics_view(engine, schema, name), (engine, name)
            assert f"`{name}`" in text or f"{schema}.{name}`" in text, name
    if getattr(system_schemas, "COLUMN_VALUE_COLUMNS", None):
        for column in ("LOW_VALUE", "HIGH_VALUE", "HIGH2KEY", "LOW2KEY"):
            assert f"`{column}`" in text, column
        assert "without a column list after its alias" in text
        assert "without * and without a column list after its " in _read(SRC / "security" / "sql_guard.py")
    if getattr(system_schemas, "CREDENTIAL_VIEWS", None):
        assert "holds stored credentials" in text
        credentials: tuple[tuple[str, str | None, str], ...] = (
            ("postgres", "information_schema", "user_mapping_options"),
            ("mysql", "mysql", "user"),
            ("mssql", "sys", "sql_logins"),
            ("oracle", None, "V$DATABASE_LINK"),
        )
        for dialect, owner, view in credentials:
            assert system_schemas.is_credential_view(dialect, owner, view), (dialect, view)
            assert view in text, view


_GUARD_REFUSALS = {
    # a message of the guard, and what tools.md says about it
    "server and session variables (@@name) are not permitted": "`@@",
    "user variables (@name) are not permitted on MySQL": "user variables",
    "PostgreSQL decodes the Unicode escapes of a U&": "`U&",
    "is not permitted on PostgreSQL outside the operators @>, <@, @@ and @?": "`@>`",
    "database links / remote-object references (@link) are not permitted": "database link",
    "IN with nothing after it, or IN right after IN": "`IN` with nothing after it",
    "names a table or dictionary in its": "`joinGet`",
    "IN (<name>) with a single name is not permitted on ClickHouse": "`x IN ((t AS z))`",
    "name a tuple's element by its index": "by its index",
}


def test_tools_md_names_the_refusals_the_guard_added() -> None:
    guard = _read(SRC / "security" / "sql_guard.py")
    tools = _flat(DOCS / "tools.md")
    for message, said in _GUARD_REFUSALS.items():
        if message in guard:
            assert said in tools, said


def test_security_md_gives_the_audit_coalescing_and_text_budget_the_log_applies() -> None:
    from universal_db_mcp.services import audit

    if not hasattr(audit, "_COALESCE_WINDOW_SECONDS"):
        return
    text = _flat(DOCS / "security.md")
    section = text[text.index("## Audit") : text.index("## Local state files")]
    assert "`tool_call_summary`" in section and "`<unknown tool>`" in section and "`<other kinds>`" in section
    assert f"{audit._COALESCE_WINDOW_SECONDS:g} s window" in section
    assert f"first {audit._COALESCE_BURST} of each kind" in section
    assert f"at most {audit._COALESCE_FULL} full records" in section
    assert f"{audit._COALESCE_KINDS} kinds" in section
    assert f"{audit._SQL_TEXT_BUDGET // (1024 * 1024)} MiB of SQL text" in section
    assert f"{audit._SQL_TEXT_ENDS} bytes" in section
    for field in ("`sql_text_omitted`", "`sql_text_tail`", "`sql_sha256`"):
        assert field in section, field
    # a statement never sent keeps no text; the per-statement records are written for statements sent
    assert "never sent" in section and "no `sql_text`" in section
    # the lock message a record that waits only the contended wait gives
    assert "after an earlier record gave up waiting {_LOCK_WAIT_SECONDS:g} s" in _read(SRC / "services" / "audit.py")
    assert f"after an earlier record gave up waiting {audit._LOCK_WAIT_SECONDS:g} s" in section


def test_the_docs_key_database_servers_as_the_executor_does() -> None:
    executor = _read(SRC / "services" / "executor.py")
    if 'f"unix_socket:' in executor:
        # a MySQL socket is the mysqld behind it: only SQLite has no database server
        stale = "MySQL through `options.unix_socket` alone"
        offenders = [str(path.relative_to(ROOT)) for path in _current_docs() if stale in _flat(path)]
        assert not offenders, offenders
    arch = _flat(DOCS / "architecture.md")
    share = arch[arch.index("**Per-server share.**") : arch.index("**Deadlines and cancel.**")]
    if 'f"tns_alias:' in executor:
        assert "`options.tns_alias`" in share and "`tns_admin`" in share
    if 'f"unix_socket:' in executor:
        assert "`options.unix_socket`" in share


def test_the_docs_say_bootstrap_orders_release_sticks() -> None:
    bootstrap = _read(ROOT / "packaging" / "trust-bootstrap-linux" / "bootstrap.sh")
    if 'RELEASE_DST="$TRUST_DIR/RELEASE"' not in bootstrap:
        return
    stale = ("Nothing orders release sticks", "does not order sticks", "a replayed older signed stick passes bootstrap")
    offenders = {f"{path.relative_to(ROOT)}: {s}" for path in _current_docs() for s in stale if s in _flat(path)}
    assert not offenders, offenders
    runbook = _flat(RUNBOOK)
    for needle in ("trust-bootstrap-linux/RELEASE", "/usr/local/lib/udbmcp-trust/RELEASE", "nothing recorded yet"):
        assert needle in runbook, needle
    assert "bootstrap.sh --stick" in runbook and "--allow-downgrade" in runbook
    assert "trust-bootstrap-linux/RELEASE" in _flat(SECURITY)
    assert "nothing recorded yet" in _residuals()


def test_offline_deployment_describes_the_installers_private_copy() -> None:
    installer = _read(ROOT / "scripts" / "install_offline.sh")
    if "root's temporary files are not made there" not in installer:
        return
    text = _flat(DOCS / "offline-deployment.md")
    for needle in (
        "`UDBMCP_STAGING_DIR`",
        "`TMPDIR`, `TEMP` and `TMP`",
        "root's temporary files are not made there",
        "udbmcp-install.XXXXXX/bundle",
        "not a regular file or directory in the bundle",
    ):
        assert needle in text, needle
    assert "not a regular file or directory in the bundle" in _read(ROOT / "scripts" / "verify_bundle.py")
    # a bundle copied with hard links is refused, so the docs say how to copy one
    assert "cp -al" in text and "--link-dest" in text


def test_the_macos_docs_name_where_launchd_writes_the_daemon_output() -> None:
    plist = _read(ROOT / "packaging" / "launchd" / "com.udbmcp.server.plist")
    if "/Library/Logs/universal-db-mcp/server.err.log" not in plist:
        return
    for path in (DOCS / "offline-deployment.md", DOCS / "troubleshooting.md"):
        text = _flat(path)
        assert "/Library/Logs/universal-db-mcp" in text, path.name
        assert "/var/log/universal-db-mcp/server.err.log" not in text, path.name
    if not (ROOT / "packaging" / "launchd" / "udbmcp.newsyslog.conf").exists():
        assert "/etc/newsyslog.d/udbmcp.conf" in _flat(DOCS / "offline-deployment.md")


def test_the_docs_give_the_default_deny_spelling_and_binding_refusals() -> None:
    guard = _read(SRC / "security" / "sql_guard.py")
    server = _read(SRC / "server.py")
    tools = _flat(DOCS / "tools.md")
    if "is not spelled as the catalog lists it on connection" in guard:
        assert "is not spelled as the catalog lists it" in tools
    if "def _check_bindings" in server:
        assert "a bare name is looked up in" in tools
    if "def _check_synonyms" in server:
        # a PUBLIC synonym of a SYS view is checked as that view, so no document says it stays readable
        stale = ("`ALL_USERS` through a PUBLIC synonym", "pg_roles or ALL_USERS stay reachable")
        offenders = {f"{path.relative_to(ROOT)}: {s}" for path in _current_docs() for s in stale if s in _flat(path)}
        assert not offenders, offenders
        assert "refused as that is" in _flat(DOCS / "security.md")


def test_tools_md_describes_the_query_history_as_the_server_does() -> None:
    if "Redacted operational history of this server process" not in _read(SRC / "server.py"):
        return
    row = next(line for line in _read(DOCS / "tools.md").splitlines() if line.startswith("| `db_get_query_history`"))
    assert "every client's calls" in row and "not a substitute for the audit log" in row.lower()


def test_the_rollback_and_package_docs_name_the_files_the_scripts_keep() -> None:
    if "metadata.sqlite.pre-rollback" in _read(ROOT / "scripts" / "rollback_offline.sh"):
        assert "metadata.sqlite.pre-rollback" in _flat(DOCS / "offline-upgrade-rollback.md")
    if "/var/lib/universal-db-mcp-package" in _read(ROOT / "packaging" / "deb" / "postrm"):
        assert "/var/lib/universal-db-mcp-package" in _flat(DOCS / "offline-deployment.md")


def test_driver_matrix_names_the_clickhouse_profile_settings_that_refuse_a_connection() -> None:
    from universal_db_mcp.connectors import clickhouse

    if not hasattr(clickhouse, "_CH_READING_SETTINGS"):
        return
    text = _read(DOCS / "driver-matrix.md")
    start = text.index("-- ClickHouse")
    block = " ".join(text[start : text.index("```", start)].split())
    for name in clickhouse._CH_READING_SETTINGS:
        assert name in block, name
    assert "compatibility" in block


def test_the_runbook_lists_this_waves_upgrade_visible_changes() -> None:
    text = _read(RUNBOOK)
    section = " ".join(text[text.index("## Behaviour changes in this release") : text.index("## Rollback")].split())
    markers = {
        # something in the code, and what the runbook's behaviour changes must name for it
        (SRC / "connectors" / "mysql.py", "_MYSQL_LEXING_MODES"): "`sql_mode`",
        (SRC / "connectors" / "postgres.py", "_PG_PIN_READING"): "`standard_conforming_strings",
        (SRC / "connectors" / "mssql.py", "_MSSQL_PIN_READING"): "`QUOTED_IDENTIFIER",
        (SRC / "services" / "audit.py", "tool_call_summary"): "`tool_call_summary`",
        (SRC / "security" / "sql_guard.py", "is not spelled as the catalog lists it"): "catalog spells",
        (SRC / "discovery" / "system_schemas.py", "CREDENTIAL_VIEWS"): "stored credentials",
        (SRC / "discovery" / "system_schemas.py", "COLUMN_STATISTICS_VIEWS"): "column statistics",
        (ROOT / "packaging" / "trust-bootstrap-linux" / "bootstrap.sh", "RELEASE_DST"): "trust-bootstrap-linux/RELEASE",
    }
    for (path, marker), said in markers.items():
        if marker in _read(path):
            assert said in section, said


def test_the_ledger_records_the_convergence_wave() -> None:
    wave = _ledger_part("**Convergence wave (2026-09-29).**", "**Residuals that remain open**")
    for needle in ("class", "re-attack", "round 1", "round 2", "round 3", "`credential_views`"):
        assert needle in wave.lower(), needle
    # the five findings the re-attack rounds confirmed, each named with its fix
    for needle in ("user_mapping_options", "`cp -a BUNDLE/. STAGING/`", "spelled", "synonym", "newsyslog"):
        assert needle in wave, needle


# ---- convergence fix-up (2026-09-29): the review of that stage's documents ---


def test_no_document_says_a_system_schema_closes_a_bare_postgres_dictionary_name() -> None:
    """Without default-deny and without an allowlist the guard checks a bare
    name in the schemas the policy-scoped listing places it in, and that
    listing holds a system schema's objects only where the schema is opened,
    when reading them is allowed anyway. Live on mock_pg (2026-09-29,
    default_deny_objects: false): `SELECT rolname FROM pg_roles` is valid
    while `pg_catalog.pg_roles` is AUTHORIZATION_DENIED."""
    stale = re.compile(r"unless the catalog places (?:the name|it) in a system schema")
    offenders = [
        str(path.relative_to(ROOT)) for path in _current_docs() if stale.search(_flat(path).replace(" # ", " "))
    ]
    assert not offenders, offenders
    readable = re.compile(r"`?pg_roles`?[^.]* stays readable although `?pg_catalog`? is closed")
    config = _flat(ROOT / "config.example.yaml").replace(" # ", " ")
    for where, text in (("security.md", _flat(DOCS / "security.md")), ("ledger", _residuals()), ("config", config)):
        assert readable.search(text), where


def test_the_docs_say_what_a_client_cancel_changed() -> None:
    """The committed release already discarded a connection after a client
    cancel (AppContext.poisoned_connectors), for later calls only: the
    statement ran on and the requests queued on the connection used it. This
    release cuts the driver call off as on a deadline: the executor poisons
    the connection at once, so those requests are refused, and fires the
    engine's cancel hook."""
    executor = _read(SRC / "services" / "executor.py")
    if "except anyio.get_cancelled_exc_class():" not in executor or "poisoned_connectors" not in _read(
        SRC / "server.py"
    ):
        return
    stale = ("poisoned only on the deadline", "now discards the connection, as a deadline does")
    offenders = {f"{path.relative_to(ROOT)}: {s}" for path in _current_docs() for s in stale if s in _flat(path)}
    assert not offenders, offenders
    runbook = _flat(RUNBOOK)
    changes = runbook[runbook.index("## Behaviour changes in this release") : runbook.index("## Rollback")]
    cancel = changes[changes.index("A client cancel during a driver call") :]
    cancel = cancel[: cancel.index("- **")]
    for needle in ("cancel hook", "`KILL QUERY`", "uncertain state", "already discarded"):
        assert needle in cancel, needle
    arch = _flat(DOCS / "architecture.md")
    deadlines = arch[arch.index("**Deadlines and cancel.**") : arch.index("**Breaker.**")]
    assert "already discarded" in deadlines and "queued" in deadlines
    wave = _ledger_part("**Convergence wave (2026-09-29).**", "**Residuals that remain open**")
    assert "committed release already" in wave and "cancel hook" in wave


def test_security_md_bounds_the_summaries_a_window_writes_as_the_log_does() -> None:
    """The kinds past the tracked ones share one `<other kinds>` summary per
    caller and outcome, and a process's refusals have one caller and two
    outcomes (deny, error): 64 summaries of kinds and two more."""
    from universal_db_mcp.server import _coalesced
    from universal_db_mcp.services import audit

    if not hasattr(audit, "_Coalescer"):
        return
    outcomes = [outcome for outcome in ("allow", "deny", "error", "cancelled") if _coalesced(outcome, False)]
    coalescer = audit._Coalescer()
    for outcome in outcomes:
        for i in range(4 * audit._COALESCE_KINDS):
            coalescer.admit(("caller", f"{outcome}-{i}", outcome, "CATEGORY", "c", None), {})
    summaries = len(coalescer.take(close=True))
    text = _flat(DOCS / "security.md")
    section = text[text.index("## Audit") : text.index("## Local state files")]
    assert f"at most {audit._COALESCE_FULL} full records and {summaries} summaries per window" in section
    for outcome in outcomes:
        assert f"`{outcome}`" in section[section.index("`<other kinds>`") :], outcome


def test_the_site_dates_its_test_count_as_the_ledger_does() -> None:
    from datetime import date, datetime

    ledger = _flat(LEDGER)
    at = ledger.index("**Test status after this review:**")
    ran = re.search(r"\bon (\d{4}-\d{2}-\d{2})\b", ledger[at : at + 600])
    footer = re.search(r"Test count as of (\d{1,2} [A-Z][a-z]+ \d{4})", _read(PAGE))
    assert ran is not None and footer is not None
    assert datetime.strptime(footer.group(1), "%d %B %Y").date() == date.fromisoformat(ran.group(1))


def _undenied_guard(engine: str) -> SqlGuard:
    """A guard with no allowlist and no default-deny: only the statement's
    form can refuse it."""
    body: dict[str, Any] = {"type": engine, "host": "h", "database": "d", "username_env": "U"}
    policy = EffectivePolicy.build(
        SecurityConfig(default_deny_objects=False),
        type("R", (), {"config": ConnectionConfig.model_validate(body), "name": "c"})(),
    )
    return SqlGuard(engine, policy, None)


def _parse_refused(guard: SqlGuard, sql: str) -> bool:
    try:
        guard.validate_select(sql)
    except ToolFailure as exc:
        return "could not be parsed" in str(exc)
    return False


_Q_LITERALS = (
    "SELECT q'[x]' AS a FROM t",
    "SELECT n FROM t WHERE c = q'{it's}'",
    "SELECT nq'!x!' FROM t",
    "SELECT Q'<a@b>' FROM t",
)


def test_the_oracle_docs_say_the_guard_cannot_parse_alternative_quoted_literals() -> None:
    """sqlglot cannot read q'...' or nq'...', so the guard refuses a statement
    holding one as a parse error in every tool, db_validate_query included,
    with or without an '@'; the connector's q-and-@ rule stays behind it."""
    oracle = _undenied_guard("oracle")
    refused = all(_parse_refused(oracle, sql) for sql in _Q_LITERALS)
    said = "the guard cannot parse an alternative-quoted"
    for path in (DOCS / "security.md", DOCS / "tools.md", DOCS / "oracle-connect-modes.md"):
        assert (said in _flat(path)) == refused, path.name
    assert (said in _residuals()) == refused
    if refused:
        assert "literal and an `@` anywhere is refused as a database link" not in _residuals()


def test_the_docs_quote_both_database_link_refusals() -> None:
    """The guard refuses t@lnk, "DUAL"@lnk and t @lnk first, in every tool;
    the Oracle connector's own text is met only past the guard."""
    guard = "database links / remote-object references (@link) are not permitted"
    connector = "database links (@link) are not permitted on connection"
    if guard not in _read(SRC / "security" / "sql_guard.py") or connector not in _connector("oracle"):
        return
    rows = [line for line in _read(DOCS / "troubleshooting.md").splitlines() if guard in line]
    assert len(rows) == 1 and connector in rows[0]
    security = _flat(DOCS / "security.md")
    assert guard in security and connector in security


@pytest.mark.skipif(sys.platform == "win32", reason="the rule is checked on POSIX paths")
def test_security_md_scopes_the_hard_link_rule_to_the_client_directories_it_covers(tmp_path: Path) -> None:
    """A hard link elsewhere to <lib_dir>/network/admin/tnsnames.ora (the
    Instant Client's default TNS_ADMIN) is refused at load only where the
    config checks that directory's files by inode, as it does tns_admin,
    wallet_location and lib_dir/../network/admin."""
    import yaml

    from universal_db_mcp.config import load_config
    from universal_db_mcp.errors import ConfigError

    admin = tmp_path / "instantclient" / "network" / "admin"
    admin.mkdir(parents=True)
    (admin / "tnsnames.ora").write_text("X=\n")
    os.link(admin / "tnsnames.ora", tmp_path / "audit.jsonl")
    options = {"thick_mode": True, "lib_dir": str(tmp_path / "instantclient")}
    conn = {"type": "oracle", "host": "db.internal", "database": "ORCLPDB1", "username_env": "U", "options": options}
    cfg = tmp_path / "config.yaml"
    body = {"application": {"audit_path": str(tmp_path / "audit.jsonl")}, "connections": {"ora": conn}}
    cfg.write_text(yaml.safe_dump(body), encoding="utf-8")
    try:
        load_config(cfg)
        refused = False
    except ConfigError as exc:
        refused = "Oracle client reads" in str(exc)
    text = _flat(DOCS / "security.md")
    client = text[text.index("- **Oracle client files.**") : text.index("## Transport")]
    assert ("Symlinks and hard links to a client file count as that file" in client) == refused
    assert ("a hard link elsewhere to a file in those two directories" in client) == (not refused)
    modes = _flat(DOCS / "oracle-connect-modes.md")
    assert ("a hard link elsewhere to a file there is not refused at load" in modes) == (not refused)


def test_offline_deployment_says_which_nt_service_names_the_msi_refuses() -> None:
    """Get-ServiceAccountSid derives a service SID for any NT SERVICE\\<name>
    without asking the local security authority, so NT SERVICE\\ALL SERVICES
    is taken as a virtual account; only the name ALL SERVICES, which the
    authority translates to S-1-5-80-0, is the group Test-AccountSid
    refuses."""
    service = _read(ROOT / "packaging" / "msi" / "custom" / "service.ps1")
    body = service[service.index("function Get-ServiceAccountSid") :]
    body = body[: body.index("\n}\n")]
    if not re.search(r"-match '\^NT SERVICE\\\\\(\.\+\)\$'\) \{\s*\$hash", body):
        return  # the action checks the NT SERVICE name now
    text = _flat(DOCS / "offline-deployment.md")
    assert "`NT SERVICE\\ALL SERVICES` (`S-1-5-80-0`) included" not in text
    assert "`ALL SERVICES` (`S-1-5-80-0`)" in text and "virtual account of that service name" in text


def test_the_docs_give_the_private_copy_the_modes_cp_leaves() -> None:
    """cp -RP without -p keeps each file's source mode (less the umask) and
    chmod -R go-rwx removes only the group and other bits: a 0444 file
    becomes 0400, a 0555 directory 0500 (GNU cp, checked in a Linux
    container)."""
    installer = _read(ROOT / "scripts" / "install_offline.sh")
    if 'cp -RP -- "$1"/. "$copy" && $sudo_ok chmod -R go-rwx "$copy"' not in installer:
        return
    stale = (
        "files are root-owned 0600 or 0700",
        "no owners, modes or links kept",
        "keeps none of the bundle's owners or modes",
    )
    offenders = {f"{path.relative_to(ROOT)}: {s}" for path in _current_docs() for s in stale if s in _flat(path)}
    assert not offenders, offenders
    for path in (DOCS / "offline-deployment.md", RUNBOOK, LEDGER):
        assert "owner bits" in _flat(path), path.name


def test_the_rollback_doc_says_what_the_upgrade_backs_up_at_metadata_sqlite() -> None:
    """[ -f ] follows a link and is false for a FIFO: a link to a regular file
    is copied as a link, anything else is not backed up."""
    if "[ -f /var/lib/universal-db-mcp/metadata.sqlite ] &&" not in _read(ROOT / "scripts" / "upgrade_offline.sh"):
        return
    text = _flat(DOCS / "offline-upgrade-rollback.md")
    assert "is kept as such" not in text
    assert "copied as a link" in text and "(a FIFO, a dangling link) is not backed up" in text


def test_config_example_names_every_clickhouse_reading_setting() -> None:
    from universal_db_mcp.connectors import clickhouse

    if not hasattr(clickhouse, "_CH_READING_SETTINGS"):
        return
    text = _flat(ROOT / "config.example.yaml").replace(" # ", " ")
    at = text.index("ClickHouse: the account's settings profile")
    comment = text[at : text.index("PostgreSQL example", at)]
    for name in clickhouse._CH_READING_SETTINGS:
        assert name in comment, name
    assert "compatibility unset or above 21.x" in comment
