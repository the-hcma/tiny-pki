"""Issue CA, server, and client certificates (PEM bytes in / out).

Extracted and generalized from ``the-hcma/my-tracks`` ``app/pki.py`` (MIT).
"""

from __future__ import annotations

import ipaddress
import warnings
from datetime import UTC, datetime, timedelta
from typing import Literal

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tiny_pki._rsa import load_rsa_private_key
from tiny_pki.constants import (
    ALLOWED_KEY_SIZES,
    APPLE_MAX_SERVER_VALIDITY_DAYS,
    CLOCK_SKEW_BACKDATE,
    DEFAULT_CA_KEY_SIZE,
    DEFAULT_CA_VALIDITY_DAYS,
    DEFAULT_CLIENT_VALIDITY_DAYS,
    DEFAULT_LEAF_KEY_SIZE,
    DEFAULT_ORGANIZATION_NAME,
    DEFAULT_SERVER_VALIDITY_DAYS,
    MAX_CLIENT_VALIDITY_DAYS,
    MAX_SERVER_VALIDITY_DAYS,
)
from tiny_pki.errors import TinyPkiWarning


def generate_ca_certificate(
    common_name: str = "Private CA",
    *,
    organization_name: str = DEFAULT_ORGANIZATION_NAME,
    validity_days: int = DEFAULT_CA_VALIDITY_DAYS,
    key_size: int = DEFAULT_CA_KEY_SIZE,
) -> tuple[bytes, bytes]:
    """Generate a self-signed CA certificate and private key.

    The validity window is backdated by ``CLOCK_SKEW_BACKDATE`` so relying parties
    with slightly slow clocks accept the certificate immediately; the encoded
    period stays exactly ``validity_days``.

    Returns:
        Tuple of ``(certificate_pem, private_key_pem)``.

    Raises:
        ValueError: If ``key_size`` is not in ``ALLOWED_KEY_SIZES`` or names are empty.
    """
    _require_non_empty(common_name, "common_name")
    _require_non_empty(organization_name, "organization_name")
    _require_key_size(key_size)
    _require_validity_days(validity_days)

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        ]
    )
    not_before, not_after = _validity_window(validity_days)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return _pem_pair(cert, key)


def generate_client_certificate(
    ca_cert_pem: bytes,
    ca_key_pem: bytes,
    common_name: str,
    *,
    organization_name: str | None = None,
    validity_days: int = DEFAULT_CLIENT_VALIDITY_DAYS,
    key_size: int = DEFAULT_LEAF_KEY_SIZE,
    allow_long_validity: bool = False,
) -> tuple[bytes, bytes]:
    """Generate a client (CLIENT_AUTH) certificate signed by the given CA.

    ``common_name`` is the identity embedded in the CN (person, device, or service).

    When ``organization_name`` is omitted, the CA certificate's O is reused, falling
    back to ``DEFAULT_ORGANIZATION_NAME`` if the CA has no O attribute.

    Raises:
        ValueError: If ``validity_days`` exceeds ``MAX_CLIENT_VALIDITY_DAYS`` without
            ``allow_long_validity=True``, or the certificate would outlive the CA.
    """
    _require_non_empty(common_name, "common_name")
    _require_key_size(key_size)
    _require_validity_days(validity_days)

    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key = load_rsa_private_key(ca_key_pem)
    not_before, not_after = _leaf_validity_window(
        ca_cert, validity_days, kind="client", allow_long_validity=allow_long_validity
    )
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    org = organization_name
    if org is None:
        ca_org_attrs = ca_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        org = str(ca_org_attrs[0].value) if ca_org_attrs else DEFAULT_ORGANIZATION_NAME
    else:
        _require_non_empty(org, "organization_name")

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(client_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return _pem_pair(cert, client_key)


def generate_server_certificate(
    ca_cert_pem: bytes,
    ca_key_pem: bytes,
    common_name: str,
    san_entries: list[str],
    *,
    organization_name: str | None = None,
    validity_days: int = DEFAULT_SERVER_VALIDITY_DAYS,
    key_size: int = DEFAULT_LEAF_KEY_SIZE,
    allow_long_validity: bool = False,
) -> tuple[bytes, bytes]:
    """Generate a server (SERVER_AUTH) certificate signed by the given CA.

    ``san_entries`` must contain at least one DNS name or IP address.

    Raises:
        ValueError: If ``validity_days`` exceeds ``MAX_SERVER_VALIDITY_DAYS`` without
            ``allow_long_validity=True``, or the certificate would outlive the CA.

    Warns:
        TinyPkiWarning: When an override exceeds ``APPLE_MAX_SERVER_VALIDITY_DAYS``
            (Apple platforms reject such server certificates).
    """
    _require_non_empty(common_name, "common_name")
    _require_key_size(key_size)
    _require_validity_days(validity_days)
    if not san_entries:
        raise ValueError("Expected at least one SAN entry, got empty list")

    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key = load_rsa_private_key(ca_key_pem)
    not_before, not_after = _leaf_validity_window(
        ca_cert, validity_days, kind="server", allow_long_validity=allow_long_validity
    )
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    org = organization_name
    if org is None:
        ca_org_attrs = ca_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        org = str(ca_org_attrs[0].value) if ca_org_attrs else DEFAULT_ORGANIZATION_NAME
    else:
        _require_non_empty(org, "organization_name")

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        ]
    )
    san_objects: list[x509.GeneralName] = []
    for entry in san_entries:
        try:
            addr = ipaddress.ip_address(entry)
            san_objects.append(x509.IPAddress(addr))
        except ValueError:
            san_objects.append(x509.DNSName(entry))

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName(san_objects), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return _pem_pair(cert, server_key)


def _leaf_validity_window(
    ca_cert: x509.Certificate,
    validity_days: int,
    *,
    kind: Literal["client", "server"],
    allow_long_validity: bool,
) -> tuple[datetime, datetime]:
    """Return ``(not_before, not_after)`` after enforcing lifetime policy."""
    cap = MAX_SERVER_VALIDITY_DAYS if kind == "server" else MAX_CLIENT_VALIDITY_DAYS
    if validity_days > cap and not allow_long_validity:
        raise ValueError(
            f"Expected validity_days <= {cap} for {kind} certificates, got {validity_days}; "
            "pass allow_long_validity=True (CLI: --allow-long-validity) to override"
        )
    if kind == "server" and validity_days > APPLE_MAX_SERVER_VALIDITY_DAYS:
        warnings.warn(
            f"Server certificate validity {validity_days} days exceeds "
            f"{APPLE_MAX_SERVER_VALIDITY_DAYS}; Apple platforms will reject it",
            TinyPkiWarning,
            stacklevel=3,
        )
    not_before, not_after = _validity_window(validity_days)
    ca_not_after = ca_cert.not_valid_after_utc
    if not_after > ca_not_after:
        remaining_days = max((ca_not_after - not_before).days, 0)
        raise ValueError(
            f"Expected {kind} certificate to expire by the CA's notAfter "
            f"({ca_not_after.isoformat()}), got validity_days={validity_days}; "
            f"use validity_days <= {remaining_days} or renew the CA"
        )
    return not_before, not_after


def _pem_pair(cert: x509.Certificate, key: rsa.RSAPrivateKey) -> tuple[bytes, bytes]:
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def _require_key_size(key_size: int) -> None:
    if key_size not in ALLOWED_KEY_SIZES:
        raise ValueError(f"Expected key_size in {ALLOWED_KEY_SIZES}, got {key_size}")


def _require_non_empty(value: str, field_name: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"Expected a non-empty {field_name}")


def _require_validity_days(validity_days: int) -> None:
    if validity_days <= 0:
        raise ValueError(f"Expected validity_days > 0, got {validity_days}")


def _validity_window(validity_days: int) -> tuple[datetime, datetime]:
    """Backdate the whole window so the encoded period is exactly ``validity_days``."""
    not_before = datetime.now(UTC) - CLOCK_SKEW_BACKDATE
    return not_before, not_before + timedelta(days=validity_days)
