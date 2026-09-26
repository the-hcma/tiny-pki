"""Unambiguous lookups and revoke-before-delete (issue #100)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography import x509
from hamcrest import assert_that, calling, contains_string, equal_to, has_item, raises

from tiny_pki import (
    generate_ca_certificate,
    generate_client_certificate,
    get_certificate_expiry,
    get_certificate_fingerprint,
    get_certificate_serial_number,
)
from tiny_pki.cli.main import main
from tiny_pki.store import CertificateStore


@pytest.fixture(scope="module")
def ca_pair() -> tuple[bytes, bytes]:
    return generate_ca_certificate(key_size=2048)


def _add(store: CertificateStore, ca_pair: tuple[bytes, bytes], cn: str) -> int:
    cert_pem, key_pem = generate_client_certificate(*ca_pair, cn, key_size=2048)
    serial = get_certificate_serial_number(cert_pem)
    store.add_certificate(
        common_name=cn,
        kind="client",
        serial_number=serial,
        cert_pem=cert_pem,
        key_pem=key_pem,
        not_valid_after=get_certificate_expiry(cert_pem),
        fingerprint=get_certificate_fingerprint(cert_pem),
    )
    return serial


def _store_with_lookalike(tmp_path: Path, ca_pair: tuple[bytes, bytes]) -> tuple[CertificateStore, str]:
    store = CertificateStore(tmp_path / "store")
    store.write_ca(*ca_pair)
    victim_serial = format(_add(store, ca_pair, "victim"), "x")
    _add(store, ca_pair, victim_serial)
    return store, victim_serial


def test_serial_that_is_another_cn_is_ambiguous(tmp_path: Path, ca_pair: tuple[bytes, bytes]) -> None:
    store, victim_serial = _store_with_lookalike(tmp_path, ca_pair)
    assert_that(calling(store.get_certificate).with_args(victim_serial), raises(ValueError, "identify one"))


def test_0x_prefixed_cn_lookalike_is_ambiguous(tmp_path: Path, ca_pair: tuple[bytes, bytes]) -> None:
    store = CertificateStore(tmp_path / "store")
    store.write_ca(*ca_pair)
    victim_serial = format(_add(store, ca_pair, "victim"), "x")
    _add(store, ca_pair, f"0x{victim_serial}")
    assert_that(calling(store.get_certificate).with_args(f"0x{victim_serial}"), raises(ValueError, "identify one"))
    entry = store.get_certificate("victim")
    assert entry is not None
    assert_that(entry.serial_number, equal_to(victim_serial))


def test_cli_revoke_by_cn_works_despite_serial_lookalike(
    tmp_path: Path, ca_pair: tuple[bytes, bytes], capsys: pytest.CaptureFixture[str]
) -> None:
    store, victim_serial = _store_with_lookalike(tmp_path, ca_pair)
    main(["--store", str(store.root), "--color", "never", "revoke", "victim"])
    assert_that([format(s, "x") for s, _ in store.revoked_entries()], equal_to([victim_serial]))


def test_serial_lookup_without_collision(tmp_path: Path, ca_pair: tuple[bytes, bytes]) -> None:
    store = CertificateStore(tmp_path / "store")
    store.write_ca(*ca_pair)
    serial = format(_add(store, ca_pair, "alice"), "x")
    entry = store.get_certificate(serial.upper())
    assert entry is not None
    assert_that(entry.common_name, equal_to("alice"))


def test_cli_revoke_refuses_ambiguous_identity(
    tmp_path: Path, ca_pair: tuple[bytes, bytes], capsys: pytest.CaptureFixture[str]
) -> None:
    store, victim_serial = _store_with_lookalike(tmp_path, ca_pair)
    capsys.readouterr()
    with pytest.raises(SystemExit):
        main(["--store", str(store.root), "--color", "never", "revoke", victim_serial])
    assert_that(capsys.readouterr().err, contains_string("identify one"))
    assert_that(store.revoked_entries(), equal_to([]))


def test_cli_delete_force_revokes_and_lists_serial_in_crl(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = tmp_path / "store"
    base = ["--store", str(root), "--color", "never"]
    main([*base, "init", "--cn", "Delete CA", "--key-size", "2048"])
    main([*base, "create", "client", "bob", "--key-size", "2048"])
    store = CertificateStore(root)
    entry = store.get_certificate("bob")
    assert entry is not None
    serial = int(entry.serial_number, 16)
    capsys.readouterr()
    main([*base, "delete", "bob", "--force"])
    assert_that(capsys.readouterr().out, contains_string("revoked and deleted bob"))
    crl_pem = store.read_crl()
    assert crl_pem is not None
    assert_that([r.serial_number for r in x509.load_pem_x509_crl(crl_pem)], has_item(serial))
    assert_that(store.get_certificate("bob"), equal_to(None))
