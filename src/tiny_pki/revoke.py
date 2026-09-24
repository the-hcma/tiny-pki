"""Certificate Revocation List (CRL) generation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from tiny_pki._rsa import load_rsa_private_key
from tiny_pki.constants import CLOCK_SKEW_BACKDATE


def generate_crl(
    ca_cert_pem: bytes,
    ca_key_pem: bytes,
    revoked_entries: list[tuple[int, datetime]],
    *,
    validity_days: int = 30,
    crl_number: int | None = None,
) -> bytes:
    """Generate a CRL signed by the CA.

    The CRL carries the RFC 5280-required ``CRLNumber`` and
    ``AuthorityKeyIdentifier`` extensions.

    Args:
        ca_cert_pem: CA certificate in PEM format.
        ca_key_pem: CA private key in PEM format (unencrypted).
        revoked_entries: ``(serial_number, revocation_datetime)`` tuples.
        validity_days: Days until the CRL's next-update time.
        crl_number: Monotonically increasing CRL number. Defaults to the current
            time in microseconds since the epoch, which increases as long as the
            signing host's clock does not go backwards; pass a persisted counter
            if that is not guaranteed.

    Returns:
        CRL in PEM format.

    Raises:
        ValueError: If ``validity_days`` is not positive or ``crl_number`` is
            negative or longer than 20 octets.
    """
    if validity_days <= 0:
        raise ValueError(f"Expected validity_days > 0, got {validity_days}")

    now = datetime.now(UTC)
    number = crl_number if crl_number is not None else (now - _EPOCH) // timedelta(microseconds=1)
    if number < 0 or number.bit_length() > _MAX_CRL_NUMBER_BITS:
        raise ValueError(f"Expected crl_number between 0 and 2**{_MAX_CRL_NUMBER_BITS} - 1, got {number}")

    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key = load_rsa_private_key(ca_key_pem)

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now - CLOCK_SKEW_BACKDATE)
        .next_update(now + timedelta(days=validity_days))
        .add_extension(x509.CRLNumber(number), critical=False)
        .add_extension(_authority_key_identifier(ca_cert, ca_key.public_key()), critical=False)
    )
    for serial_number, revocation_time in revoked_entries:
        revoked_cert = (
            x509.RevokedCertificateBuilder().serial_number(serial_number).revocation_date(revocation_time).build()
        )
        builder = builder.add_revoked_certificate(revoked_cert)

    crl = builder.sign(ca_key, hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.PEM)


_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
# RFC 5280 §5.2.3: conforming CRL numbers fit in 20 octets (a non-negative INTEGER).
_MAX_CRL_NUMBER_BITS = 159


def _authority_key_identifier(
    ca_cert: x509.Certificate, ca_public_key: rsa.RSAPublicKey
) -> x509.AuthorityKeyIdentifier:
    """Match the CA's own SubjectKeyIdentifier when present, else derive from its key."""
    try:
        ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    except x509.ExtensionNotFound:
        return x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_public_key)
    return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)
