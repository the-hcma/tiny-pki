"""PKCS#12 (.p12) bundling for client handoff."""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from tiny_pki._rsa import load_rsa_private_key
from tiny_pki.constants import MIN_PKCS12_PASSWORD_LENGTH
from tiny_pki.errors import TinyPkiError


def generate_pkcs12(
    cert_pem: bytes,
    key_pem: bytes,
    ca_cert_pem: bytes,
    friendly_name: str,
    password: bytes,
    *,
    legacy: bool = False,
) -> bytes:
    """Bundle cert + key + CA chain into a password-protected PKCS#12 archive.

    By default the bundle uses ``cryptography``'s best available encryption
    (AES-256-CBC with PBKDF2-HMAC-SHA256 and an HMAC-SHA256 MAC). ``legacy=True``
    uses PBES1 3DES with a SHA-1 MAC instead, for older Android / Apple keychains
    that cannot import the modern format; only use it when a device requires it.

    Raises:
        TinyPkiError: If ``friendly_name`` is empty or ``password`` is shorter than
            ``MIN_PKCS12_PASSWORD_LENGTH`` bytes.
    """
    if not friendly_name or not friendly_name.strip():
        raise TinyPkiError("Expected a non-empty friendly_name")
    if len(password) < MIN_PKCS12_PASSWORD_LENGTH:
        raise TinyPkiError(f"Expected a password of at least {MIN_PKCS12_PASSWORD_LENGTH} bytes, got {len(password)}")

    cert = x509.load_pem_x509_certificate(cert_pem)
    key = load_rsa_private_key(key_pem)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)

    encryption: serialization.KeySerializationEncryption
    if legacy:
        encryption = (
            serialization.PrivateFormat.PKCS12.encryption_builder()
            .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
            .hmac_hash(hashes.SHA1())
            .build(password)
        )
    else:
        encryption = serialization.BestAvailableEncryption(password)
    return pkcs12.serialize_key_and_certificates(
        name=friendly_name.encode(),
        key=key,
        cert=cert,
        cas=[ca_cert],
        encryption_algorithm=encryption,
    )
