"""Optional Fernet helpers for encrypting private keys at rest.

Callers pass an explicit secret string — this module never reads Django
settings or environment variables.

The Fernet key is derived with HKDF-SHA256 (RFC 5869) over the secret, using
a fixed ``info`` label (``DEFAULT_INFO``) for domain separation: the derived
key is independent of anything else the application derives from the same
secret, so passing an already multi-purpose secret (e.g. Django's
``SECRET_KEY``) does not hand out a key another component also computes. It
does not help if the secret itself leaks — the label is public. HKDF is not a
password-hashing KDF either, so the secret must already be high-entropy.

``info=None`` selects the legacy derivation (a single SHA-256 of the secret)
so tokens written before HKDF can still be read and rotated with
:func:`reencrypt_private_key`. Encrypting requires a secret of at least
``MIN_SECRET_LENGTH`` characters; decrypting accepts any non-empty secret so
keys stored under a weaker one can still be rotated.
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from tiny_pki.errors import TinyPkiError

DEFAULT_INFO = b"tiny-pki:fernet-key:v1"
MIN_SECRET_LENGTH = 32


def decrypt_private_key(encrypted_data: bytes, secret: str, *, info: bytes | None = DEFAULT_INFO) -> bytes:
    """Decrypt a Fernet token produced by :func:`encrypt_private_key`."""
    _require_secret(secret)
    return Fernet(_derive_fernet_key(secret, info)).decrypt(encrypted_data)


def derive_fernet_key(secret: str, *, info: bytes | None = DEFAULT_INFO) -> bytes:
    """Derive a Fernet-compatible key from a high-entropy secret string."""
    _require_strong_secret(secret)
    return _derive_fernet_key(secret, info)


def encrypt_private_key(pem_data: bytes, secret: str, *, info: bytes | None = DEFAULT_INFO) -> bytes:
    """Encrypt PEM private-key bytes for storage at rest."""
    _require_strong_secret(secret)
    if not pem_data:
        raise TinyPkiError("Expected non-empty pem_data")
    return Fernet(_derive_fernet_key(secret, info)).encrypt(pem_data)


def reencrypt_private_key(
    encrypted_data: bytes,
    old_secret: str,
    new_secret: str,
    *,
    old_info: bytes | None = DEFAULT_INFO,
    new_info: bytes | None = DEFAULT_INFO,
) -> bytes:
    """Decrypt with ``old_secret`` / ``old_info`` and re-encrypt with ``new_secret`` / ``new_info``."""
    pem_data = decrypt_private_key(encrypted_data, old_secret, info=old_info)
    return encrypt_private_key(pem_data, new_secret, info=new_info)


def _derive_fernet_key(secret: str, info: bytes | None) -> bytes:
    if info is None:
        digest = hashlib.sha256(secret.encode()).digest()
    elif not info:
        raise TinyPkiError("Expected a non-empty info label, or None for the legacy derivation")
    else:
        digest = HKDF(algorithm=SHA256(), length=32, salt=None, info=info).derive(secret.encode())
    return base64.urlsafe_b64encode(digest)


def _require_secret(secret: str) -> None:
    if not secret or not secret.strip():
        raise TinyPkiError("Expected a non-empty secret")


def _require_strong_secret(secret: str) -> None:
    _require_secret(secret)
    if len(secret) < MIN_SECRET_LENGTH:
        raise TinyPkiError(f"Expected a secret of at least {MIN_SECRET_LENGTH} characters, got {len(secret)}")
