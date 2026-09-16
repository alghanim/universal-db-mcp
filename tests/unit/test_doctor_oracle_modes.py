"""doctor: Oracle Thick-mode and TNS-alias prerequisites.

Both fail at connect time with a driver-level error that reads like a network
problem, so doctor reports them up front. doctor must NOT load the Instant
Client to check it: init_oracle_client() switches the whole process to Thick
mode permanently, which a diagnostic command must never do as a side effect.
"""

from __future__ import annotations

from pathlib import Path

import pytest

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
    """Without lib_dir (the documented Linux route) doctor reports whether the
    loader can see the client. It is not fatal: ORACLE_HOME and other loader
    configurations can make the client available in ways the cache lookup does
    not show."""
    cfg = _config(tmp_path, "      thick_mode: true\n")
    check = _checks(run_doctor(cfg), "connection-o-oracle-instant-client")[0]
    assert check["status"] != "fatal", check
    assert "loader" in str(check["detail"]).lower()


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


# ------------------------------------------------- wallet contents, not just the directory
# Thin mode reads a PEM wallet (ewallet.pem); an orapki wallet directory
# (cwallet.sso / ewallet.p12) satisfied the old directory-exists check and then
# failed at connect time with a raw driver error - doctor reported green for a
# connection that could never work.


def _tls_config(tmp_path: Path, wallet: Path, thick: bool = False) -> str:
    ca = tmp_path / "ca.pem"
    ca.write_text("x", encoding="utf-8")
    p = tmp_path / "tls.yaml"
    p.write_text(
        "connections:\n  o:\n    type: oracle\n    host: h\n    database: svc\n"
        f"    tls:\n      enabled: true\n      verify_server: true\n      ca_file: {ca}\n"
        f"    options:\n      wallet_location: {wallet}\n"
        + ("      thick_mode: true\n" if thick else ""),
        encoding="utf-8",
    )
    return str(p)


def test_orapki_wallet_without_pem_is_fatal_in_thin_mode(tmp_path: Path) -> None:
    wallet = tmp_path / "wallet"
    wallet.mkdir()
    (wallet / "cwallet.sso").write_bytes(b"\x00")
    check = _checks(run_doctor(_tls_config(tmp_path, wallet)), "connection-o-oracle-wallet")[0]
    assert check["status"] == "fatal", check
    assert "ewallet.pem" in str(check["detail"])


def test_pem_wallet_passes(tmp_path: Path) -> None:
    wallet = tmp_path / "wallet"
    wallet.mkdir()
    (wallet / "ewallet.pem").write_text("x", encoding="utf-8")
    check = _checks(run_doctor(_tls_config(tmp_path, wallet)), "connection-o-oracle-wallet")[0]
    assert check["status"] == "ok", check


def test_thick_mode_accepts_an_orapki_wallet(tmp_path: Path) -> None:
    wallet = tmp_path / "wallet"
    wallet.mkdir()
    (wallet / "cwallet.sso").write_bytes(b"\x00")
    check = _checks(run_doctor(_tls_config(tmp_path, wallet, thick=True)), "connection-o-oracle-wallet")[0]
    assert check["status"] == "ok", check


# ------------------------------------------------- is the client actually loadable?
# With ldconfig (the documented Linux route) there is no lib_dir to check, so
# doctor used to say only "it must be on the search path". It now asks the
# loader whether it can see libclntsh - without dlopen'ing it, which would put
# this process into Thick mode permanently.


def test_reports_when_the_loader_cannot_see_the_instant_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from universal_db_mcp.diagnostics import doctor as doctor_module

    monkeypatch.setattr(doctor_module, "find_library", lambda _name: None)
    cfg = _config(tmp_path, "      thick_mode: true\n")
    check = _checks(run_doctor(cfg), "connection-o-oracle-instant-client")[0]
    assert check["status"] != "ok", check
    assert "ldconfig" in str(check["detail"])


def test_reports_when_the_loader_can_see_the_instant_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from universal_db_mcp.diagnostics import doctor as doctor_module

    monkeypatch.setattr(doctor_module, "find_library", lambda _name: "libclntsh.so.19.1")
    cfg = _config(tmp_path, "      thick_mode: true\n")
    check = _checks(run_doctor(cfg), "connection-o-oracle-instant-client")[0]
    assert check["status"] == "ok", check
    assert "libclntsh" in str(check["detail"])
