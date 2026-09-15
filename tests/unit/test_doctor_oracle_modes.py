"""doctor: Oracle Thick-mode and TNS-alias prerequisites.

Both fail at connect time with a driver-level error that reads like a network
problem, so doctor reports them up front. doctor must NOT load the Instant
Client to check it: init_oracle_client() switches the whole process to Thick
mode permanently, which a diagnostic command must never do as a side effect.
"""

from __future__ import annotations

from pathlib import Path

from universal_db_mcp.diagnostics.doctor import run_doctor


def _checks(report: object, name: str) -> list[dict[str, object]]:
    found = [c for c in report["checks"] if c["check"] == name]  # type: ignore[index]
    assert found, f"doctor produced no '{name}' check"
    return found  # type: ignore[return-value]


def _config(tmp_path: Path, options: str) -> str:
    p = tmp_path / "c.yaml"
    p.write_text(
        "connections:\n  o:\n    type: oracle\n    host: h\n    database: svc\n"
        "    options:\n" + options,
        encoding="utf-8",
    )
    return str(p)


def test_missing_instant_client_dir_is_fatal(tmp_path: Path) -> None:
    cfg = _config(
        tmp_path, f"      thick_mode: true\n      lib_dir: {tmp_path / 'no_instantclient'}\n"
    )
    check = _checks(run_doctor(cfg), "connection-o-oracle-instant-client")[0]
    assert check["status"] == "fatal", check


def test_present_instant_client_dir_passes(tmp_path: Path) -> None:
    lib = tmp_path / "instantclient_23_5"
    lib.mkdir()
    cfg = _config(tmp_path, f"      thick_mode: true\n      lib_dir: {lib}\n")
    check = _checks(run_doctor(cfg), "connection-o-oracle-instant-client")[0]
    assert check["status"] == "ok", check


def test_thick_mode_without_lib_dir_is_reported_not_fatal(tmp_path: Path) -> None:
    cfg = _config(tmp_path, "      thick_mode: true\n")
    check = _checks(run_doctor(cfg), "connection-o-oracle-instant-client")[0]
    assert check["status"] != "fatal", check
    assert "search path" in str(check["detail"]).lower()


def test_tns_alias_without_tnsnames_file_is_fatal(tmp_path: Path) -> None:
    tns = tmp_path / "tns"
    tns.mkdir()
    cfg = _config(tmp_path, f"      tns_alias: PRODDB\n      tns_admin: {tns}\n")
    check = _checks(run_doctor(cfg), "connection-o-oracle-tnsnames")[0]
    assert check["status"] == "fatal", check


def test_tns_alias_with_tnsnames_file_passes(tmp_path: Path) -> None:
    tns = tmp_path / "tns"
    tns.mkdir()
    (tns / "tnsnames.ora").write_text("PRODDB = (DESCRIPTION=())\n", encoding="utf-8")
    cfg = _config(tmp_path, f"      tns_alias: PRODDB\n      tns_admin: {tns}\n")
    check = _checks(run_doctor(cfg), "connection-o-oracle-tnsnames")[0]
    assert check["status"] == "ok", check
