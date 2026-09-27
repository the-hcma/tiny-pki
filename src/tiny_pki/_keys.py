"""Internal helpers for generating and loading RSA and ECDSA P-256 private keys."""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from tiny_pki.constants import ALLOWED_KEY_SIZES, KEY_TYPES
from tiny_pki.errors import TinyPkiError

PrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey


def generate_private_key(rsa_key_size: int | None) -> PrivateKey:
    """Generate the key :func:`require_key_params` resolved: RSA of that size, or P-256 for ``None``."""
    if rsa_key_size is None:
        return ec.generate_private_key(ec.SECP256R1())
    return rsa.generate_private_key(public_exponent=65537, key_size=rsa_key_size)


def load_private_key(key_pem: bytes) -> PrivateKey:
    """Load an unencrypted RSA or ECDSA P-256 private key from PEM bytes.

    Raises:
        TinyPkiError: If the PEM is not an unencrypted RSA or P-256 private key
            (including when cryptography raises ``TypeError`` for an
            encrypted key with ``password=None``).
    """
    try:
        key = serialization.load_pem_private_key(key_pem, password=None)
    except TypeError as exc:
        raise TinyPkiError(
            "Expected an unencrypted PEM private key; got an encrypted key "
            f"(password was not given but private key is encrypted): {exc}"
        ) from exc
    if isinstance(key, rsa.RSAPrivateKey):
        return key
    if isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(key.curve, ec.SECP256R1):
        return key
    raise TinyPkiError(f"Expected an RSA or ECDSA P-256 private key, got {_describe(key)}")


def load_ca_private_key(ca_cert: x509.Certificate, ca_key_pem: bytes) -> PrivateKey:
    """Load the CA key with :func:`load_private_key` and require it to match ``ca_cert``.

    Raises:
        TinyPkiError: If the key cannot be loaded or belongs to a different certificate.
    """
    key = load_private_key(ca_key_pem)
    spki = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    if key.public_key().public_bytes(*spki) != ca_cert.public_key().public_bytes(*spki):
        raise TinyPkiError("Expected the CA private key to match the CA certificate's public key")
    return key


def require_key_params(key_type: object, key_size: object, *, default_size: int) -> int | None:
    """Validate ``key_type`` / ``key_size`` and return the RSA size to use (``None`` for EC)."""
    if key_type not in KEY_TYPES:
        raise TinyPkiError(f"Expected key_type in {KEY_TYPES}, got {key_type!r}")
    if key_type == "ec-p256":
        if key_size is not None:
            raise TinyPkiError(f"Expected no key_size with key_type 'ec-p256' (P-256 has a fixed size), got {key_size}")
        return None
    size = default_size if key_size is None else key_size
    if isinstance(size, bool) or not isinstance(size, int) or size not in ALLOWED_KEY_SIZES:
        raise TinyPkiError(f"Expected key_size in {ALLOWED_KEY_SIZES}, got {size!r}")
    return size


def _describe(key: object) -> str:
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return f"an EC key on {key.curve.name}"
    return type(key).__name__
