"""Optional Fernet helpers for encrypting private keys at rest.

Callers pass an explicit secret string — this module never reads Django
settings or environment variables.

The Fernet key is derived with a single SHA-256 of the secret (urlsafe
base64). That is intentional for explicit-secret callers that already
manage secret strength; it is not a password-hashing KDF. Encrypting
requires a secret of at least ``MIN_SECRET_LENGTH`` characters; decrypting
accepts any non-empty secret so keys stored under a weaker one can still be
rotated with :func:`reencrypt_private_key`.
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet

from tiny_pki.errors import TinyPkiError

MIN_SECRET_LENGTH = 32


def decrypt_private_key(encrypted_data: bytes, secret: str) -> bytes:
    """Decrypt a Fernet token produced by :func:`encrypt_private_key`."""
    _require_secret(secret)
    return Fernet(_derive_fernet_key(secret)).decrypt(encrypted_data)


def derive_fernet_key(secret: str) -> bytes:
    """Derive a Fernet-compatible key from a high-entropy secret string."""
    _require_strong_secret(secret)
    return _derive_fernet_key(secret)


def encrypt_private_key(pem_data: bytes, secret: str) -> bytes:
    """Encrypt PEM private-key bytes for storage at rest."""
    _require_strong_secret(secret)
    if not pem_data:
        raise TinyPkiError("Expected non-empty pem_data")
    return Fernet(_derive_fernet_key(secret)).encrypt(pem_data)


def reencrypt_private_key(encrypted_data: bytes, old_secret: str, new_secret: str) -> bytes:
    """Decrypt with ``old_secret`` and re-encrypt with ``new_secret``."""
    pem_data = decrypt_private_key(encrypted_data, old_secret)
    return encrypt_private_key(pem_data, new_secret)


def _derive_fernet_key(secret: str) -> bytes:
    digest = hashlib.sha256(secret.encode()).digest()
    return base64.urlsafe_b64encode(digest)


def _require_secret(secret: str) -> None:
    if not secret or not secret.strip():
        raise TinyPkiError("Expected a non-empty secret")


def _require_strong_secret(secret: str) -> None:
    _require_secret(secret)
    if len(secret) < MIN_SECRET_LENGTH:
        raise TinyPkiError(f"Expected a secret of at least {MIN_SECRET_LENGTH} characters, got {len(secret)}")
