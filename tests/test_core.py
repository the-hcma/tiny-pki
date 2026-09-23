"""Unit tests for tiny_pki core crypto (issue / inspect / revoke / bundle)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from typing import cast

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID
from hamcrest import (
    assert_that,
    calling,
    contains_string,
    equal_to,
    greater_than,
    has_item,
    has_length,
    instance_of,
    is_,
    not_none,
    raises,
    starts_with,
)

from tiny_pki import (
    ALLOWED_KEY_SIZES,
    generate_ca_certificate,
    generate_client_certificate,
    generate_crl,
    generate_pkcs12,
    generate_server_certificate,
    get_certificate_expiry,
    get_certificate_fingerprint,
    get_certificate_issuer,
    get_certificate_metadata,
    get_certificate_sans,
    get_certificate_serial_number,
    get_certificate_subject,
    is_certificate_self_signed,
)
from tiny_pki._rsa import load_rsa_private_key

# Split so secret scanners do not treat assertion fixtures as live PEM material.
_PEM_CERT_PREFIX = "-----BEGIN " + "CERTIFICATE-----"
_PEM_KEY_PREFIX = "-----BEGIN " + "PRIVATE KEY-----"


class TestGenerateCaCertificate:
    def test_returns_pem(self) -> None:
        cert_pem, key_pem = generate_ca_certificate()
        assert_that(cert_pem.decode(), starts_with(_PEM_CERT_PREFIX))
        assert_that(key_pem.decode(), starts_with(_PEM_KEY_PREFIX))

    def test_custom_cn_and_org(self) -> None:
        cert_pem, _ = generate_ca_certificate(
            common_name="Home Warden CA",
            organization_name="hcma",
        )
        assert_that(get_certificate_subject(cert_pem), equal_to("Home Warden CA"))
        assert_that(get_certificate_metadata(cert_pem)["O"], equal_to("hcma"))

    def test_is_ca_with_key_usage(self) -> None:
        cert_pem, _ = generate_ca_certificate(key_size=2048)
        cert = x509.load_pem_x509_certificate(cert_pem)
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert_that(bc.value.ca, is_(True))
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert_that(ku.value.key_cert_sign, is_(True))
        assert_that(ku.value.crl_sign, is_(True))

    def test_custom_validity(self) -> None:
        cert_pem, _ = generate_ca_certificate(validity_days=365)
        cert = x509.load_pem_x509_certificate(cert_pem)
        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        assert_that(delta.days, equal_to(365))

    def test_default_key_size_4096(self) -> None:
        cert_pem, _ = generate_ca_certificate()
        public_key = x509.load_pem_x509_certificate(cert_pem).public_key()
        assert_that(public_key, instance_of(RSAPublicKey))
        rsa_key = cast(RSAPublicKey, public_key)
        assert_that(rsa_key.key_size, equal_to(4096))

    def test_invalid_key_size(self) -> None:
        assert_that(
            calling(generate_ca_certificate).with_args(key_size=1024),
            raises(ValueError, "Expected key_size in"),
        )

    def test_empty_common_name(self) -> None:
        assert_that(
            calling(generate_ca_certificate).with_args(common_name="  "),
            raises(ValueError, "non-empty common_name"),
        )

    def test_allowed_key_sizes_constant(self) -> None:
        assert_that(ALLOWED_KEY_SIZES, equal_to((2048, 3072, 4096)))

    def test_invalid_validity_days(self) -> None:
        assert_that(
            calling(generate_ca_certificate).with_args(validity_days=0),
            raises(ValueError, "validity_days > 0"),
        )
        assert_that(
            calling(generate_ca_certificate).with_args(validity_days=-1),
            raises(ValueError, "validity_days > 0"),
        )

    def test_self_signed(self) -> None:
        cert_pem, _ = generate_ca_certificate()
        assert_that(is_certificate_self_signed(cert_pem), is_(True))

    def test_same_dn_as_ca_is_not_self_signed(self) -> None:
        ca_cert, ca_key = generate_ca_certificate(
            common_name="Foo",
            organization_name="Bar",
            key_size=2048,
        )
        client_pem, _ = generate_client_certificate(
            ca_cert,
            ca_key,
            "Foo",
            organization_name="Bar",
            key_size=2048,
        )
        assert_that(get_certificate_subject(client_pem), equal_to("Foo"))
        assert_that(get_certificate_issuer(client_pem), equal_to("Foo"))
        assert_that(is_certificate_self_signed(client_pem), is_(False))


class TestGenerateServerCertificate:
    def test_signed_by_ca_with_sans(self) -> None:
        ca_cert, ca_key = generate_ca_certificate(key_size=2048)
        cert_pem, key_pem = generate_server_certificate(
            ca_cert,
            ca_key,
            "mqtt.local",
            ["mqtt.local", "127.0.0.1"],
            key_size=2048,
        )
        assert_that(cert_pem.decode(), starts_with(_PEM_CERT_PREFIX))
        assert_that(key_pem.decode(), starts_with(_PEM_KEY_PREFIX))
        assert_that(get_certificate_issuer(cert_pem), equal_to(get_certificate_subject(ca_cert)))
        assert_that(is_certificate_self_signed(cert_pem), is_(False))
        sans = get_certificate_sans(cert_pem)
        assert_that(sans, has_item("mqtt.local"))
        assert_that(sans, has_item("127.0.0.1"))
        cert = x509.load_pem_x509_certificate(cert_pem)
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        assert_that(
            san_ext.value.get_values_for_type(x509.IPAddress),
            equal_to([ipaddress.ip_address("127.0.0.1")]),
        )
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert_that(list(eku.value), has_item(ExtendedKeyUsageOID.SERVER_AUTH))

    def test_empty_sans_raises(self) -> None:
        ca_cert, ca_key = generate_ca_certificate(key_size=2048)
        assert_that(
            calling(generate_server_certificate).with_args(ca_cert, ca_key, "cn", []),
            raises(ValueError, "SAN entry"),
        )


class TestGenerateClientCertificate:
    def test_client_auth_cn(self) -> None:
        ca_cert, ca_key = generate_ca_certificate(
            common_name="Test CA",
            organization_name="Acme",
            key_size=2048,
        )
        cert_pem, _ = generate_client_certificate(ca_cert, ca_key, "alice", key_size=2048)
        assert_that(get_certificate_subject(cert_pem), equal_to("alice"))
        assert_that(get_certificate_metadata(cert_pem)["O"], equal_to("Acme"))
        cert = x509.load_pem_x509_certificate(cert_pem)
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert_that(list(eku.value), has_item(ExtendedKeyUsageOID.CLIENT_AUTH))

    def test_empty_identity_raises(self) -> None:
        ca_cert, ca_key = generate_ca_certificate(key_size=2048)
        assert_that(
            calling(generate_client_certificate).with_args(ca_cert, ca_key, ""),
            raises(ValueError, "non-empty common_name"),
        )


class TestInspectAndCrlAndPkcs12:
    def test_fingerprint_format(self) -> None:
        cert_pem, _ = generate_ca_certificate(key_size=2048)
        parts = get_certificate_fingerprint(cert_pem).split(":")
        assert_that(parts, has_length(32))

    def test_expiry_and_serial(self) -> None:
        cert_pem, _ = generate_ca_certificate(key_size=2048, validity_days=100)
        assert_that(get_certificate_expiry(cert_pem), instance_of(datetime))
        assert_that(get_certificate_serial_number(cert_pem), greater_than(0))

    def test_sans_absent_on_ca(self) -> None:
        cert_pem, _ = generate_ca_certificate(key_size=2048)
        assert_that(get_certificate_sans(cert_pem), equal_to([]))

    def test_generate_crl_with_revocation(self) -> None:
        ca_cert, ca_key = generate_ca_certificate(key_size=2048)
        client_pem, _ = generate_client_certificate(ca_cert, ca_key, "bob", key_size=2048)
        serial = get_certificate_serial_number(client_pem)
        crl_pem = generate_crl(ca_cert, ca_key, [(serial, datetime.now(UTC))])
        assert_that(crl_pem.decode(), contains_string("BEGIN X509 CRL"))
        crl = x509.load_pem_x509_crl(crl_pem)
        assert_that(crl.get_revoked_certificate_by_serial_number(serial), is_(not_none()))

    def test_generate_crl_rejects_non_positive_validity(self) -> None:
        ca_cert, ca_key = generate_ca_certificate(key_size=2048)
        assert_that(
            calling(generate_crl).with_args(ca_cert, ca_key, [], validity_days=0),
            raises(ValueError, "validity_days > 0"),
        )

    def test_generate_pkcs12_roundtrip(self) -> None:
        ca_cert, ca_key = generate_ca_certificate(key_size=2048)
        cert_pem, key_pem = generate_client_certificate(ca_cert, ca_key, "carol", key_size=2048)
        p12 = generate_pkcs12(cert_pem, key_pem, ca_cert, "carol", b"secret")
        assert_that(
            calling(pkcs12.load_key_and_certificates).with_args(p12, b"wrong"),
            raises(ValueError),
        )
        key, cert, additional = pkcs12.load_key_and_certificates(p12, b"secret")
        assert_that(key, is_(not_none()))
        assert_that(cert, is_(not_none()))
        assert_that(additional, has_length(1))

    def test_generate_pkcs12_rejects_empty_name_or_password(self) -> None:
        ca_cert, ca_key = generate_ca_certificate(key_size=2048)
        cert_pem, key_pem = generate_client_certificate(ca_cert, ca_key, "carol", key_size=2048)
        assert_that(
            calling(generate_pkcs12).with_args(cert_pem, key_pem, ca_cert, "", b"secret"),
            raises(ValueError, "friendly_name"),
        )
        assert_that(
            calling(generate_pkcs12).with_args(cert_pem, key_pem, ca_cert, "carol", b""),
            raises(ValueError, "password"),
        )

    def test_load_rsa_private_key_rejects_encrypted_pem(self) -> None:
        _, key_pem = generate_ca_certificate(key_size=2048)
        key = load_rsa_private_key(key_pem)
        encrypted_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"pw"),
        )
        assert_that(
            calling(load_rsa_private_key).with_args(encrypted_pem),
            raises(ValueError, "encrypted"),
        )
