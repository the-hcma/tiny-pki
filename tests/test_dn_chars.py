"""Leaf CNs refuse RFC 4514 special characters by default (issue #124)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID
from hamcrest import assert_that, calling, contains_string, equal_to, raises
from pytest import CaptureFixture

from tiny_pki import TinyPkiError, generate_ca_certificate, generate_client_certificate, generate_server_certificate
from tiny_pki.cli.main import main
from tiny_pki.store import CertificateStore

_CA = generate_ca_certificate("DN CA", key_size=2048)


def _cn(cert_pem: bytes) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem)
    return str(cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)


@pytest.mark.parametrize("common_name", ["bob,CN=alice", "eve+CN=alice", "a=b", 'say"hi"', "a<b", "a>b", "a;b"])
def test_client_cn_with_dn_special_character_is_refused(common_name: str) -> None:
    assert_that(
        calling(generate_client_certificate).with_args(*_CA, common_name, key_size=2048),
        raises(TinyPkiError, "DN special character"),
    )


def test_client_cn_with_leading_hash_is_refused() -> None:
    assert_that(
        calling(generate_client_certificate).with_args(*_CA, "#alice", key_size=2048),
        raises(TinyPkiError, "leading '#'"),
    )


def test_server_cn_with_dn_special_character_is_refused() -> None:
    assert_that(
        calling(generate_server_certificate).with_args(*_CA, "api,CN=home", ["api.home"], key_size=2048),
        raises(TinyPkiError, "DN special character ','"),
    )


def test_opt_out_issues_the_cn_verbatim() -> None:
    cert_pem, _ = generate_client_certificate(*_CA, "bob,CN=alice", key_size=2048, allow_dn_special_chars=True)
    assert_that(_cn(cert_pem), equal_to("bob,CN=alice"))
    server_pem, _ = generate_server_certificate(
        *_CA, "api+home", ["api.home"], key_size=2048, allow_dn_special_chars=True
    )
    assert_that(_cn(server_pem), equal_to("api+home"))


def test_ordinary_cns_still_pass() -> None:
    assert_that(
        _cn(generate_client_certificate(*_CA, "Alice Smith (phone)", key_size=2048)[0]), equal_to("Alice Smith (phone)")
    )
    assert_that(_cn(generate_client_certificate(*_CA, "a#b", key_size=2048)[0]), equal_to("a#b"))


def test_cli_create_refuses_dn_special_character(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    store = tmp_path / "store"
    _cli(store, "init", "--key-size", "2048")
    capsys.readouterr()
    with pytest.raises(SystemExit):
        _cli(store, "create", "client", "bob,CN=alice", "--key-size", "2048")
    assert_that(capsys.readouterr().err, contains_string("--allow-dn-special-chars"))
    assert_that(CertificateStore(store).list_certificates(status="all"), equal_to([]))


def test_cli_create_allows_opt_out(tmp_path: Path) -> None:
    store = tmp_path / "store"
    _cli(store, "init", "--key-size", "2048")
    _cli(store, "create", "client", "--allow-dn-special-chars", "bob,CN=alice", "--key-size", "2048")
    entry = CertificateStore(store).get_certificate("bob,CN=alice")
    assert entry is not None
    assert_that(_cn(CertificateStore(store).read_certificate_pem(entry)), equal_to("bob,CN=alice"))


def _cli(store: Path, *words: str) -> None:
    main(["--store", str(store), "--color", "never", *words])


def test_cli_create_server_refuses_and_allows_opt_out(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    store = tmp_path / "store"
    _cli(store, "init", "--key-size", "2048")
    capsys.readouterr()
    with pytest.raises(SystemExit):
        _cli(store, "create", "server", "api,CN=home", "--san", "api.home", "--key-size", "2048")
    assert_that(capsys.readouterr().err, contains_string("DN special character ','"))
    assert_that(CertificateStore(store).list_certificates(status="all"), equal_to([]))
    _cli(store, "create", "server", "--allow-dn-special-chars", "api+home", "--san", "api.home", "--key-size", "2048")
    entry = CertificateStore(store).get_certificate("api+home")
    assert entry is not None
    assert_that(_cn(CertificateStore(store).read_certificate_pem(entry)), equal_to("api+home"))
