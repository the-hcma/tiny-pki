"""Certificate introspection helpers (PEM in, structured fields out)."""

from __future__ import annotations

from datetime import datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

_OID_TO_LABEL: dict[x509.ObjectIdentifier, str] = {
    NameOID.COMMON_NAME: "CN",
    NameOID.COUNTRY_NAME: "C",
    NameOID.LOCALITY_NAME: "L",
    NameOID.ORGANIZATION_NAME: "O",
    NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
    NameOID.STATE_OR_PROVINCE_NAME: "ST",
}


def get_certificate_expiry(cert_pem: bytes) -> datetime:
    """Return the expiry datetime of a PEM-encoded certificate (UTC)."""
    cert = x509.load_pem_x509_certificate(cert_pem)
    return cert.not_valid_after_utc


def get_certificate_fingerprint(cert_pem: bytes) -> str:
    """Return the SHA-256 fingerprint as a colon-separated hex string."""
    cert = x509.load_pem_x509_certificate(cert_pem)
    digest = cert.fingerprint(hashes.SHA256())
    return ":".join(f"{b:02X}" for b in digest)


def get_certificate_issuer(cert_pem: bytes) -> str:
    """Return the issuer common name, or the full issuer DN (RFC 4514) if CN is absent."""
    cert = x509.load_pem_x509_certificate(cert_pem)
    cn_attrs = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn_attrs:
        return str(cn_attrs[0].value)
    return cert.issuer.rfc4514_string()


def get_certificate_metadata(cert_pem: bytes) -> dict[str, str]:
    """Extract subject fields (CN, O, OU, C, ST, L) present on the certificate."""
    cert = x509.load_pem_x509_certificate(cert_pem)
    metadata: dict[str, str] = {}
    for oid, label in _OID_TO_LABEL.items():
        attrs = cert.subject.get_attributes_for_oid(oid)
        if attrs:
            metadata[label] = str(attrs[0].value)
    return metadata


def get_certificate_sans(cert_pem: bytes) -> list[str]:
    """Return DNS and IP Subject Alternative Names as strings."""
    cert = x509.load_pem_x509_certificate(cert_pem)
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    names: list[str] = []
    for name in san_ext.value.get_values_for_type(x509.DNSName):
        names.append(str(name))
    for addr in san_ext.value.get_values_for_type(x509.IPAddress):
        names.append(str(addr))
    return names


def get_certificate_serial_number(cert_pem: bytes) -> int:
    """Return the certificate serial number as an integer."""
    cert = x509.load_pem_x509_certificate(cert_pem)
    return cert.serial_number


def get_certificate_subject(cert_pem: bytes) -> str:
    """Return the subject common name, or the full subject DN (RFC 4514) if CN is absent."""
    cert = x509.load_pem_x509_certificate(cert_pem)
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn_attrs:
        return str(cn_attrs[0].value)
    return cert.subject.rfc4514_string()


def is_certificate_self_signed(cert_pem: bytes) -> bool:
    """Return True when the cert is signed by its own public key.

    Requires matching issuer/subject DNs **and** a signature that verifies
    against the certificate's own public key (so a CA-issued leaf with an
    identical DN is not treated as self-signed).
    """
    cert = x509.load_pem_x509_certificate(cert_pem)
    if cert.issuer != cert.subject:
        return False
    try:
        cert.verify_directly_issued_by(cert)
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True
