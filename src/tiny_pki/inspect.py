"""Certificate introspection helpers (PEM or DER in, structured fields out)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from tiny_pki._certs import load_certificate
from tiny_pki._csr import (
    csr_problems,
    describe_public_key,
    load_csr,
    public_key_fingerprint,
    requested_extension_names,
    requested_sans,
)

_OID_TO_LABEL: dict[x509.ObjectIdentifier, str] = {
    NameOID.COMMON_NAME: "CN",
    NameOID.COUNTRY_NAME: "C",
    NameOID.LOCALITY_NAME: "L",
    NameOID.ORGANIZATION_NAME: "O",
    NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
    NameOID.STATE_OR_PROVINCE_NAME: "ST",
}


@dataclass(frozen=True)
class CertificateIdentity:
    """Who a certificate names, for authenticating a TLS peer in one call.

    ``common_name`` is the first subject CN, or ``None`` when there is none. The
    SAN tuples keep certificate order; ``fingerprint`` is formatted as by
    :func:`get_certificate_fingerprint`.
    """

    common_name: str | None
    dns_names: tuple[str, ...]
    ip_addresses: tuple[str, ...]
    uris: tuple[str, ...]
    serial_number: int
    fingerprint: str


@dataclass(frozen=True)
class CsrSummary:
    """What a certificate signing request asks for, and whether tiny-pki would sign it.

    ``public_key_fingerprint`` is the SHA-256 of the DER SubjectPublicKeyInfo,
    the value to compare with the device owner out of band. ``problems`` lists
    every reason :func:`tiny_pki.sign_client_csr` would refuse the CSR; it is
    empty when the CSR can be signed.
    """

    subject: str
    common_name: str | None
    sans: tuple[str, ...]
    key_type: str
    key_size: int | None
    signature_hash: str | None
    public_key_fingerprint: str
    requested_extensions: tuple[str, ...]
    problems: tuple[str, ...]


def inspect_csr(csr_pem: bytes) -> CsrSummary:
    """Summarize a PEM or DER certificate signing request without signing it.

    Raises:
        TinyPkiError: If ``csr_pem`` is not a CSR.
    """
    csr = load_csr(csr_pem)
    cn_attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    try:
        key_type, key_size = describe_public_key(csr.public_key())
        fingerprint = public_key_fingerprint(csr)
    except (UnsupportedAlgorithm, ValueError):
        key_type, key_size, fingerprint = "unsupported", None, ""
    try:
        algorithm = csr.signature_hash_algorithm
    except UnsupportedAlgorithm:
        algorithm = None
    return CsrSummary(
        subject=csr.subject.rfc4514_string(),
        common_name=str(cn_attrs[0].value) if cn_attrs else None,
        sans=tuple(requested_sans(csr)),
        key_type=key_type,
        key_size=key_size,
        signature_hash=algorithm.name if algorithm is not None else None,
        public_key_fingerprint=fingerprint,
        requested_extensions=tuple(requested_extension_names(csr)),
        problems=tuple(csr_problems(csr)),
    )


def get_certificate_identity(cert_pem: bytes) -> CertificateIdentity:
    """Return the CN, SANs, serial number and fingerprint of a PEM or DER certificate.

    Meant for a TLS server reading its peer: pass the DER from
    ``SSLObject.getpeercert(binary_form=True)``. Read-only, so it accepts
    certificates tiny-pki would not issue (several URI SANs, no CN, and so on).
    """
    cert = load_certificate(cert_pem)
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    sans = _subject_alternative_names(cert)
    return CertificateIdentity(
        common_name=str(cn_attrs[0].value) if cn_attrs else None,
        dns_names=tuple(str(name) for name in sans.get_values_for_type(x509.DNSName)) if sans else (),
        ip_addresses=tuple(str(addr) for addr in sans.get_values_for_type(x509.IPAddress)) if sans else (),
        uris=tuple(str(uri) for uri in sans.get_values_for_type(x509.UniformResourceIdentifier)) if sans else (),
        serial_number=cert.serial_number,
        fingerprint=_fingerprint(cert),
    )


def get_certificate_expiry(cert_pem: bytes) -> datetime:
    """Return the expiry datetime of a PEM-encoded certificate (UTC)."""
    cert = load_certificate(cert_pem)
    return cert.not_valid_after_utc


def get_certificate_fingerprint(cert_pem: bytes) -> str:
    """Return the SHA-256 fingerprint as a colon-separated hex string."""
    return _fingerprint(load_certificate(cert_pem))


def get_certificate_issuer(cert_pem: bytes) -> str:
    """Return the issuer common name, or the full issuer DN (RFC 4514) if CN is absent."""
    cert = load_certificate(cert_pem)
    cn_attrs = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn_attrs:
        return str(cn_attrs[0].value)
    return cert.issuer.rfc4514_string()


def get_certificate_metadata(cert_pem: bytes) -> dict[str, str]:
    """Extract subject fields (CN, O, OU, C, ST, L) present on the certificate."""
    cert = load_certificate(cert_pem)
    metadata: dict[str, str] = {}
    for oid, label in _OID_TO_LABEL.items():
        attrs = cert.subject.get_attributes_for_oid(oid)
        if attrs:
            metadata[label] = str(attrs[0].value)
    return metadata


def get_certificate_sans(cert_pem: bytes) -> list[str]:
    """Return DNS and IP Subject Alternative Names as strings (URIs: see :func:`get_certificate_uris`)."""
    sans = _subject_alternative_names(load_certificate(cert_pem))
    if sans is None:
        return []
    names: list[str] = [str(name) for name in sans.get_values_for_type(x509.DNSName)]
    names.extend(str(addr) for addr in sans.get_values_for_type(x509.IPAddress))
    return names


def get_certificate_serial_number(cert_pem: bytes) -> int:
    """Return the certificate serial number as an integer."""
    cert = load_certificate(cert_pem)
    return cert.serial_number


def get_certificate_uris(cert_pem: bytes) -> list[str]:
    """Return the URI Subject Alternative Names (such as SPIFFE IDs), in certificate order."""
    sans = _subject_alternative_names(load_certificate(cert_pem))
    if sans is None:
        return []
    return [str(uri) for uri in sans.get_values_for_type(x509.UniformResourceIdentifier)]


def get_certificate_subject(cert_pem: bytes) -> str:
    """Return the subject common name, or the full subject DN (RFC 4514) if CN is absent."""
    cert = load_certificate(cert_pem)
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
    cert = load_certificate(cert_pem)
    if cert.issuer != cert.subject:
        return False
    try:
        cert.verify_directly_issued_by(cert)
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True


def _fingerprint(cert: x509.Certificate) -> str:
    return ":".join(f"{b:02X}" for b in cert.fingerprint(hashes.SHA256()))


def _subject_alternative_names(cert: x509.Certificate) -> x509.SubjectAlternativeName | None:
    try:
        return cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return None
