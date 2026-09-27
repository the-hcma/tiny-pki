"""ECDSA P-256 keys alongside RSA for CA and leaf issuance (issue #33)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import SignatureAlgorithmOID
from hamcrest import assert_that, calling, contains_string, equal_to, instance_of, is_, raises
from pytest import CaptureFixture

from tiny_pki import (
    DEFAULT_KEY_TYPE,
    DEFAULT_LEAF_KEY_SIZE,
    KEY_TYPES,
    KeyType,
    TinyPkiError,
    generate_ca_certificate,
    generate_client_certificate,
    generate_crl,
    generate_pkcs12,
    generate_server_certificate,
)
from tiny_pki.cli.main import main
from tiny_pki.store import CertificateStore

_EC_CA = generate_ca_certificate("EC CA", key_type="ec-p256")
_RSA_CA = generate_ca_certificate("RSA CA", key_size=2048)
_CAS = {"ec-p256": _EC_CA, "rsa": _RSA_CA}
_PAIRS: list[tuple[KeyType, KeyType]] = [(ca, leaf) for ca in KEY_TYPES for leaf in KEY_TYPES]


def _cert(pem: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem)


def _leaf_kwargs(leaf_type: KeyType) -> dict[str, object]:
    return {"key_type": "ec-p256"} if leaf_type == "ec-p256" else {"key_size": 2048}


def _assert_key(pem: bytes, key_type: KeyType) -> None:
    key = _cert(pem).public_key()
    if key_type == "ec-p256":
        assert isinstance(key, ec.EllipticCurvePublicKey)
        assert_that(key.curve, instance_of(ec.SECP256R1))
    else:
        assert_that(key, instance_of(rsa.RSAPublicKey))


def _run(store: Path, *words: str, capsys: CaptureFixture[str], expect_ok: bool = True) -> tuple[str, str]:
    argv = ["--store", str(store), "--color", "never", *words]
    if expect_ok:
        main(argv)
    else:
        with pytest.raises(SystemExit):
            main(argv)
    captured = capsys.readouterr()
    return captured.out, captured.err


def test_default_key_type_is_rsa() -> None:
    assert_that(DEFAULT_KEY_TYPE, equal_to("rsa"))
    ca_cert, ca_key = _RSA_CA
    cert_pem, _ = generate_client_certificate(ca_cert, ca_key, "alice")
    key = _cert(cert_pem).public_key()
    assert isinstance(key, rsa.RSAPublicKey)
    assert_that(key.key_size, equal_to(DEFAULT_LEAF_KEY_SIZE))


def test_ec_ca_is_self_signed_with_ecdsa_sha256() -> None:
    cert = _cert(_EC_CA[0])
    _assert_key(_EC_CA[0], "ec-p256")
    assert_that(cert.signature_algorithm_oid, equal_to(SignatureAlgorithmOID.ECDSA_WITH_SHA256))
    cert.verify_directly_issued_by(cert)
    usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert_that((usage.key_cert_sign, usage.crl_sign), equal_to((True, True)))
    assert_that(serialization.load_pem_private_key(_EC_CA[1], None), instance_of(ec.EllipticCurvePrivateKey))


@pytest.mark.parametrize(("ca_type", "leaf_type"), _PAIRS)
def test_leaves_chain_across_key_types(ca_type: KeyType, leaf_type: KeyType) -> None:
    ca_cert, ca_key = _CAS[ca_type]
    client, _ = generate_client_certificate(ca_cert, ca_key, "alice", **_leaf_kwargs(leaf_type))  # type: ignore[arg-type]
    server, _ = generate_server_certificate(ca_cert, ca_key, "api.home", ["api.home"], **_leaf_kwargs(leaf_type))  # type: ignore[arg-type]
    for pem in (client, server):
        _assert_key(pem, leaf_type)
        _cert(pem).verify_directly_issued_by(_cert(ca_cert))
        usage = _cert(pem).extensions.get_extension_for_class(x509.KeyUsage).value
        assert_that(usage.digital_signature, is_(True))
        assert_that(usage.key_encipherment, equal_to(leaf_type == "rsa"))


@pytest.mark.parametrize("ca_type", KEY_TYPES)
def test_crl_from_either_ca_type_verifies(ca_type: KeyType) -> None:
    ca_cert, ca_key = _CAS[ca_type]
    crl = x509.load_pem_x509_crl(generate_crl(ca_cert, ca_key, [(1234, datetime.now(UTC))]))
    public_key = _cert(ca_cert).public_key()
    assert isinstance(public_key, rsa.RSAPublicKey | ec.EllipticCurvePublicKey)
    assert_that(crl.is_signature_valid(public_key), is_(True))


@pytest.mark.parametrize(("ca_type", "leaf_type"), _PAIRS)
def test_pkcs12_bundles_either_key_type(ca_type: KeyType, leaf_type: KeyType) -> None:
    ca_cert, ca_key = _CAS[ca_type]
    cert_pem, key_pem = generate_client_certificate(ca_cert, ca_key, "alice", **_leaf_kwargs(leaf_type))  # type: ignore[arg-type]
    password = b"a-long-enough-bundle-password"
    key, cert, extra = pkcs12.load_key_and_certificates(
        generate_pkcs12(cert_pem, key_pem, ca_cert, "alice", password), password
    )
    assert key is not None
    assert cert is not None
    assert_that(key.public_key(), equal_to(_cert(cert_pem).public_key()))
    assert_that([c.public_bytes(serialization.Encoding.PEM) for c in extra], equal_to([ca_cert]))


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"key_type": "ec-p256", "key_size": 2048}, "no key_size with key_type 'ec-p256'"),
        ({"key_type": "ed25519"}, "Expected key_type in"),
        ({"key_size": 1024}, "Expected key_size in"),
        ({"key_size": True}, "Expected key_size in"),
    ],
)
def test_bad_key_parameters_are_rejected(kwargs: dict[str, object], message: str) -> None:
    ca_cert, ca_key = _RSA_CA
    for call in (
        calling(generate_ca_certificate).with_args("X", **kwargs),
        calling(generate_client_certificate).with_args(ca_cert, ca_key, "alice", **kwargs),
        calling(generate_server_certificate).with_args(ca_cert, ca_key, "api.home", ["api.home"], **kwargs),
    ):
        assert_that(call, raises(TinyPkiError, message))


def test_ca_key_from_another_ca_is_rejected() -> None:
    assert_that(
        calling(generate_client_certificate).with_args(_RSA_CA[0], _EC_CA[1], "alice"),
        raises(TinyPkiError, "CA private key to match the CA certificate"),
    )
    assert_that(
        calling(generate_crl).with_args(_EC_CA[0], _RSA_CA[1], []),
        raises(TinyPkiError, "CA private key to match the CA certificate"),
    )


def test_unsupported_curve_is_rejected() -> None:
    p384 = ec.generate_private_key(ec.SECP384R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    assert_that(
        calling(generate_pkcs12).with_args(_EC_CA[0], p384, _EC_CA[0], "x", b"a-long-enough-bundle-password"),
        raises(TinyPkiError, "RSA or ECDSA P-256 private key, got an EC key on secp384r1"),
    )


def test_store_issues_ec_leaves(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "store")
    store.write_ca(*_EC_CA)
    store.publish_crl()
    client = store.issue_client("alice", key_type="ec-p256")
    server = store.issue_server("api.home", ["api.home"], key_type="ec-p256")
    for entry in (client, server):
        _assert_key(store.read_certificate_pem(entry), "ec-p256")
    store.revoke("alice")
    crl_pem = store.read_crl()
    assert crl_pem is not None
    crl = x509.load_pem_x509_crl(crl_pem)
    assert_that({e.serial_number for e in crl}, equal_to({int(client.serial_number, 16)}))


def test_cli_ec_ca_and_mixed_leaves(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    root = tmp_path / "store"
    _run(root, "init", "--cn", "EC CLI CA", "--key-type", "ec-p256", capsys=capsys)
    _run(root, "create", "client", "alice", "--key-type", "ec-p256", capsys=capsys)
    _run(root, "create", "server", "api.home", "--key-type", "EC-P256", capsys=capsys)
    _run(root, "create", "client", "bob", "--key-type", "rsa", "--key-size", "2048", capsys=capsys)
    store = CertificateStore(root)
    _assert_key(store.read_ca()[0], "ec-p256")
    for name, key_type in (("alice", "ec-p256"), ("api.home", "ec-p256"), ("bob", "rsa")):
        entry = store.get_certificate(name)
        assert entry is not None
        _assert_key(store.read_certificate_pem(entry), key_type)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("words", "message"),
    [
        (("init", "--key-type", "ec-p256", "--key-size", "2048"), "no --key-size with --key-type ec-p256"),
        (("init", "--key-type", "dsa"), "Expected --key-type in rsa, ec-p256"),
        (("init", "--key-size", "big"), "whole number for --key-size"),
        (("init", "--key-size", "1024"), "Expected key_size in"),
    ],
)
def test_cli_bad_key_flags_are_rejected(
    tmp_path: Path, capsys: CaptureFixture[str], words: tuple[str, ...], message: str
) -> None:
    root = tmp_path / "store"
    _, err = _run(root, *words, capsys=capsys, expect_ok=False)
    assert_that(err, contains_string(message))
    assert_that(CertificateStore(root).has_ca(), is_(False))


def test_cli_create_rejects_key_size_with_ec(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    root = tmp_path / "store"
    _run(root, "init", "--key-type", "ec-p256", capsys=capsys)
    _, err = _run(
        root, "create", "client", "alice", "--key-type", "ec-p256", "--key-size", "2048", capsys=capsys, expect_ok=False
    )
    assert_that(err, contains_string("no --key-size with --key-type ec-p256"))
    assert_that(CertificateStore(root).get_certificate("alice"), equal_to(None))
