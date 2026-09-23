"""PKCS#12 (.p12) bundling for client handoff."""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from tiny_pki._rsa import load_rsa_private_key


def generate_pkcs12(
    cert_pem: bytes,
    key_pem: bytes,
    ca_cert_pem: bytes,
    friendly_name: str,
    password: bytes,
) -> bytes:
    """Bundle cert + key + CA chain into a password-protected PKCS#12 archive."""
    if not friendly_name or not friendly_name.strip():
        raise ValueError("Expected a non-empty friendly_name")
    if not password:
        raise ValueError("Expected a non-empty password")

    cert = x509.load_pem_x509_certificate(cert_pem)
    key = load_rsa_private_key(key_pem)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)

    return pkcs12.serialize_key_and_certificates(
        name=friendly_name.encode(),
        key=key,
        cert=cert,
        cas=[ca_cert],
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )
