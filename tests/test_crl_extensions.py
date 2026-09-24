"""RFC 5280 CRL extensions: CRLNumber and AuthorityKeyIdentifier (issue #32)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
import time_machine
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from hamcrest import assert_that, calling, equal_to, greater_than, is_, raises

from tiny_pki import generate_ca_certificate, generate_crl
from tiny_pki._rsa import load_rsa_private_key

_CA = generate_ca_certificate("CRL Ext CA", key_size=2048)


def test_crl_aki_from_public_key_without_ski() -> None:
    _, ca_key = _CA
    key = load_rsa_private_key(ca_key)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "No SKI CA")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    crl = x509.load_pem_x509_crl(generate_crl(cert.public_bytes(serialization.Encoding.PEM), ca_key, []))
    aki = crl.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    expected = x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key())
    assert_that(aki.value.key_identifier, equal_to(expected.key_identifier))


def test_crl_carries_aki_matching_ca_ski() -> None:
    ca_cert, ca_key = _CA
    crl = x509.load_pem_x509_crl(generate_crl(ca_cert, ca_key, []))
    aki = crl.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    ski = x509.load_pem_x509_certificate(ca_cert).extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    assert_that(aki.critical, is_(False))
    assert_that(aki.value.key_identifier, equal_to(ski.value.digest))


def test_default_crl_number_increases_with_time() -> None:
    ca_cert, ca_key = _CA
    start = datetime(2026, 9, 1, tzinfo=UTC)
    numbers: list[int] = []
    for offset in (timedelta(0), timedelta(microseconds=1), timedelta(days=1)):
        with time_machine.travel(start + offset, tick=False):
            crl = x509.load_pem_x509_crl(generate_crl(ca_cert, ca_key, []))
        ext = crl.extensions.get_extension_for_class(x509.CRLNumber)
        assert_that(ext.critical, is_(False))
        numbers.append(ext.value.crl_number)
    assert_that(numbers[1], greater_than(numbers[0]))
    assert_that(numbers[2], greater_than(numbers[1]))


@pytest.mark.parametrize("number", [0, 42, 2**159 - 1])
def test_explicit_crl_number(number: int) -> None:
    ca_cert, ca_key = _CA
    crl = x509.load_pem_x509_crl(generate_crl(ca_cert, ca_key, [], crl_number=number))
    assert_that(crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number, equal_to(number))


@pytest.mark.parametrize("number", [-1, 2**159])
def test_crl_number_out_of_range(number: int) -> None:
    ca_cert, ca_key = _CA
    assert_that(
        calling(generate_crl).with_args(ca_cert, ca_key, [], crl_number=number),
        raises(ValueError, "Expected crl_number between 0 and 2\\*\\*159 - 1"),
    )
