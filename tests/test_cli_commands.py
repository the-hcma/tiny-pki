"""End-to-end tests for CLI PKI commands against a temp store."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

from pathlib import Path
from typing import cast

from cryptography import x509
from hamcrest import (
    assert_that,
    contains_string,
    equal_to,
    has_item,
    has_length,
    is_,
    is_not,
    not_none,
)
from pytest import CaptureFixture, MonkeyPatch, raises

from tiny_pki import get_certificate_sans, get_certificate_serial_number
from tiny_pki.cli.main import main
from tiny_pki.store import CertificateStore, IssuedCertificate


def _run(
    store: Path,
    *words: str,
    capsys: CaptureFixture[str],
    expect_ok: bool = True,
) -> tuple[str, str]:
    argv = ["--store", str(store), "--color", "never", *words]
    if expect_ok:
        main(argv)
    else:
        with raises(SystemExit) as exited:
            main(argv)
        assert_that(exited.value.code, equal_to(1))
    captured = capsys.readouterr()
    return captured.out, captured.err


def test_init_create_show_revoke_delete_export(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    store = tmp_path / "ca"
    out, err = _run(store, "init", "--cn", "Test CA", "--key-size", "2048", capsys=capsys)
    assert_that(err, equal_to(""))
    assert_that(out, contains_string("CA created"))

    out, err = _run(
        store,
        "create",
        "client",
        "alice",
        "--key-size",
        "2048",
        "--days",
        "365",
        capsys=capsys,
    )
    assert_that(err, equal_to(""))
    assert_that(out, contains_string("issued client alice"))

    out, err = _run(
        store,
        "create",
        "server",
        "api.example",
        "--san",
        "api.example",
        "--san",
        "127.0.0.1",
        "--key-size",
        "2048",
        capsys=capsys,
    )
    assert_that(err, equal_to(""))
    assert_that(out, contains_string("issued server api.example"))
    cs = CertificateStore(store)
    server = cs.get_certificate("api.example")
    assert_that(server, is_(not_none()))
    server_entry = cast(IssuedCertificate, server)
    sans = get_certificate_sans(cs.read_certificate_pem(server_entry))
    assert_that(sans, has_item("api.example"))
    assert_that(sans, has_item("127.0.0.1"))

    out, err = _run(store, "show", "certs", capsys=capsys)
    assert_that(out, contains_string("alice"))
    assert_that(out, contains_string("api.example"))

    out, err = _run(store, "show", "ca", capsys=capsys)
    assert_that(out, contains_string("subject"))
    assert_that(out, contains_string("valid"))

    pem_out = tmp_path / "alice.pem"
    out, err = _run(store, "export", "pem", "alice", "--out", str(pem_out), capsys=capsys)
    assert_that(err, equal_to(""))
    assert_that(pem_out.is_file(), is_(True))
    pem_text = pem_out.read_text(encoding="utf-8")
    assert_that("BEGIN CERTIFICATE" in pem_text, is_(True))
    assert_that(("BEGIN " + "PRIVATE KEY") in pem_text, is_(True))
    assert_that(oct(pem_out.stat().st_mode & 0o777), equal_to("0o600"))

    p12_out = tmp_path / "alice.p12"
    out, err = _run(
        store,
        "export",
        "p12",
        "alice",
        "--out",
        str(p12_out),
        "--password",
        "secret",
        capsys=capsys,
    )
    assert_that(err, equal_to(""))
    assert_that(p12_out.is_file(), is_(True))
    assert_that(oct(p12_out.stat().st_mode & 0o777), equal_to("0o600"))

    out, err = _run(store, "export", "p12", "alice", "--password", "secret", capsys=capsys)
    assert_that(err, equal_to(""))
    alice = cs.get_certificate("alice")
    assert_that(alice, is_(not_none()))
    alice_entry = cast(IssuedCertificate, alice)
    bundle = store / "bundles" / f"alice-{alice_entry.serial_number}.p12"
    assert_that(bundle.is_file(), is_(True))
    assert_that(oct(bundle.stat().st_mode & 0o777), equal_to("0o600"))

    # Active delete without --force must fail (and leave the cert in place).
    out, err = _run(store, "delete", "api.example", capsys=capsys, expect_ok=False)
    assert_that(err, contains_string("still active"))
    assert_that(cs.get_certificate("api.example"), is_(not_none()))

    out, err = _run(store, "revoke", "alice", capsys=capsys)
    assert_that(out, contains_string("revoked alice"))
    assert_that((store / "crl.pem").is_file(), is_(True))
    crl = x509.load_pem_x509_crl((store / "crl.pem").read_bytes())
    revoked_serials = [revoked.serial_number for revoked in crl]
    assert_that(
        revoked_serials,
        has_item(get_certificate_serial_number(cs.read_certificate_pem(alice_entry))),
    )

    out, err = _run(store, "show", "crl", capsys=capsys)
    assert_that(out, contains_string("revoked serial="))

    out, err = _run(store, "delete", "alice", capsys=capsys)
    assert_that(out, contains_string("deleted alice"))
    assert_that(cs.get_certificate("alice"), equal_to(None))
    assert_that(cs.revoked_entries(), has_length(1))
    out, err = _run(store, "crl", capsys=capsys)
    assert_that(err, equal_to(""))
    out, err = _run(store, "show", "crl", capsys=capsys)
    assert_that(out, contains_string("revoked serial="))

    # --force before identity must work (value-less flag must not swallow the CN).
    out, err = _run(store, "delete", "--force", "api.example", capsys=capsys)
    assert_that(out, contains_string("deleted api.example"))


def test_init_requires_store(capsys: CaptureFixture[str], monkeypatch: MonkeyPatch) -> None:
    monkeypatch.delenv("TINY_PKI_STORE", raising=False)
    with raises(SystemExit) as exited:
        main(["--color", "never", "init"])
    assert_that(exited.value.code, equal_to(1))
    err = capsys.readouterr().err
    assert_that(err, contains_string("Expected --store"))


def test_inspect_pem_path(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    store = tmp_path / "ca"
    _run(store, "init", "--key-size", "2048", capsys=capsys)
    ca_path = store / "ca.crt"
    out, err = _run(store, "inspect", str(ca_path), capsys=capsys)
    assert_that(err, equal_to(""))
    assert_that(out, contains_string("fingerprint"))
    assert_that(out, contains_string("subject"))
    assert_that(out, contains_string("issuer"))

    _run(store, "create", "client", "bob", "--key-size", "2048", capsys=capsys)
    out, err = _run(store, "inspect", "bob", capsys=capsys)
    assert_that(err, equal_to(""))
    assert_that(out, contains_string("fingerprint"))
    assert_that(out, contains_string("subject"))


def test_renew_crl_alias(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    store = tmp_path / "ca"
    _run(store, "init", "--key-size", "2048", capsys=capsys)
    out, err = _run(store, "renew-crl", capsys=capsys)
    assert_that(err, equal_to(""))
    assert_that(out, contains_string("crl regenerated"))


def test_create_client_rejects_san(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    store = tmp_path / "ca"
    _run(store, "init", "--key-size", "2048", capsys=capsys)
    out, err = _run(
        store,
        "create",
        "client",
        "alice",
        "--san",
        "vpn.example",
        "--key-size",
        "2048",
        capsys=capsys,
        expect_ok=False,
    )
    assert_that(err, contains_string("--san is only supported for server"))
    assert_that(out, equal_to(""))


def test_reissue_refreshes_crl(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    store = tmp_path / "ca"
    _run(store, "init", "--key-size", "2048", capsys=capsys)
    _run(store, "create", "client", "alice", "--key-size", "2048", capsys=capsys)
    cs = CertificateStore(store)
    first = cast(IssuedCertificate, cs.get_certificate("alice"))
    first_serial = int(first.serial_number, 16)
    _run(store, "create", "client", "alice", "--key-size", "2048", capsys=capsys)
    crl = x509.load_pem_x509_crl((store / "crl.pem").read_bytes())
    revoked_serials = [revoked.serial_number for revoked in crl]
    assert_that(revoked_serials, has_item(first_serial))
    second = cs.get_certificate("alice")
    assert_that(second, is_(not_none()))
    assert_that(cast(IssuedCertificate, second).serial_number, is_not(equal_to(first.serial_number)))
