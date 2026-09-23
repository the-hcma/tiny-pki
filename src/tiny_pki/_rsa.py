"""Internal helpers for loading RSA keys from PEM."""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey


def load_rsa_private_key(key_pem: bytes) -> RSAPrivateKey:
    """Load an unencrypted RSA private key from PEM bytes.

    Raises:
        ValueError: If the PEM is not an unencrypted RSA private key
            (including when cryptography raises ``TypeError`` for an
            encrypted key with ``password=None``).
    """
    try:
        key = serialization.load_pem_private_key(key_pem, password=None)
    except TypeError as exc:
        raise ValueError(
            "Expected an unencrypted PEM private key; got an encrypted key "
            f"(password was not given but private key is encrypted): {exc}"
        ) from exc
    if not isinstance(key, RSAPrivateKey):
        raise ValueError("Expected RSA private key")
    return key
