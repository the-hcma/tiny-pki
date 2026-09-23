"""Certificate Revocation List (CRL) generation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from tiny_pki._rsa import load_rsa_private_key


def generate_crl(
    ca_cert_pem: bytes,
    ca_key_pem: bytes,
    revoked_entries: list[tuple[int, datetime]],
    *,
    validity_days: int = 30,
) -> bytes:
    """Generate a CRL signed by the CA.

    Args:
        ca_cert_pem: CA certificate in PEM format.
        ca_key_pem: CA private key in PEM format (unencrypted).
        revoked_entries: ``(serial_number, revocation_datetime)`` tuples.
        validity_days: Days until the CRL's next-update time.

    Returns:
        CRL in PEM format.
    """
    if validity_days <= 0:
        raise ValueError(f"Expected validity_days > 0, got {validity_days}")

    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key = load_rsa_private_key(ca_key_pem)

    now = datetime.now(UTC)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + timedelta(days=validity_days))
    )
    for serial_number, revocation_time in revoked_entries:
        revoked_cert = (
            x509.RevokedCertificateBuilder().serial_number(serial_number).revocation_date(revocation_time).build()
        )
        builder = builder.add_revoked_certificate(revoked_cert)

    crl = builder.sign(ca_key, hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.PEM)
