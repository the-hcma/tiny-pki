"""Inspection fallbacks: full DN without a CN, and every get_certificate_metadata field (issue #62)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from hamcrest import assert_that, equal_to

from tiny_pki import get_certificate_issuer, get_certificate_metadata, get_certificate_subject


def test_issuer_without_cn_falls_back_to_full_dn() -> None:
    cert = _certificate(subject=_name(CN="leaf.home"), issuer=_name(C="US", O="No CN CA", OU="PKI"))
    assert_that(get_certificate_issuer(cert), equal_to("OU=PKI,O=No CN CA,C=US"))
    assert_that(get_certificate_subject(cert), equal_to("leaf.home"))


def test_metadata_includes_every_present_field() -> None:
    cert = _certificate(
        subject=_name(C="US", ST="California", L="San Francisco", O="Acme", OU="Ops", CN="api.home"),
        issuer=_name(CN="Metadata CA"),
    )
    assert_that(
        get_certificate_metadata(cert),
        equal_to({"CN": "api.home", "O": "Acme", "OU": "Ops", "C": "US", "ST": "California", "L": "San Francisco"}),
    )


def test_metadata_omits_absent_fields() -> None:
    cert = _certificate(subject=_name(CN="alice"), issuer=_name(CN="Metadata CA"))
    assert_that(get_certificate_metadata(cert), equal_to({"CN": "alice"}))
    no_cn = _certificate(subject=_name(O="Acme", C="US"), issuer=_name(CN="Metadata CA"))
    assert_that(get_certificate_metadata(no_cn), equal_to({"O": "Acme", "C": "US"}))


def test_subject_without_cn_falls_back_to_full_dn() -> None:
    cert = _certificate(subject=_name(C="US", O="No CN Inc", OU="Devices"), issuer=_name(CN="Fallback CA"))
    assert_that(get_certificate_subject(cert), equal_to("OU=Devices,O=No CN Inc,C=US"))
    assert_that(get_certificate_issuer(cert), equal_to("Fallback CA"))


_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_LABEL_TO_OID = {
    "C": NameOID.COUNTRY_NAME,
    "CN": NameOID.COMMON_NAME,
    "L": NameOID.LOCALITY_NAME,
    "O": NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,
}


def _certificate(*, subject: x509.Name, issuer: x509.Name) -> bytes:
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(_KEY.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .sign(_KEY, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def _name(**label_to_value: str) -> x509.Name:
    """Build a name with attributes in the given order (RFC 4514 output reverses it)."""
    return x509.Name([x509.NameAttribute(_LABEL_TO_OID[label], value) for label, value in label_to_value.items()])
