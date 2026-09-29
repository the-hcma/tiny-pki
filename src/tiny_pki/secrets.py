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
import secrets as random_secrets
import struct

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

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


def decrypt_private_key_scrypt(encrypted_data: bytes, secret: str) -> bytes:
    """Decrypt a CA-key envelope containing Scrypt parameters, salt, and Fernet token."""
    _require_secret(secret)
    header_size = _SCRYPT_PARAMS.size + _SCRYPT_SALT_SIZE
    if len(encrypted_data) <= header_size:
        raise TinyPkiError("Expected encrypted CA key data to contain Scrypt parameters, salt, and Fernet token")
    n, r, p = _SCRYPT_PARAMS.unpack(encrypted_data[: _SCRYPT_PARAMS.size])
    if (n, r, p) not in _SUPPORTED_SCRYPT_PROFILES:
        raise TinyPkiError(f"Unsupported CA-key Scrypt parameters: n={n}, r={r}, p={p}")
    salt = encrypted_data[_SCRYPT_PARAMS.size : header_size]
    token = encrypted_data[header_size:]
    return Fernet(_derive_scrypt_fernet_key(secret, salt, n=n, r=r, p=p)).decrypt(token)


def encrypt_private_key_scrypt(pem_data: bytes, secret: str) -> bytes:
    """Encrypt with a per-key salt and an envelope-recorded Scrypt profile."""
    _require_strong_secret(secret)
    if not pem_data:
        raise TinyPkiError("Expected non-empty pem_data")
    salt = random_secrets.token_bytes(_SCRYPT_SALT_SIZE)
    n, r, p = _SCRYPT_PROFILE
    token = Fernet(_derive_scrypt_fernet_key(secret, salt, n=n, r=r, p=p)).encrypt(pem_data)
    return _SCRYPT_PARAMS.pack(n, r, p) + salt + token


def _derive_fernet_key(secret: str, info: bytes | None) -> bytes:
    if info is None:
        digest = hashlib.sha256(secret.encode()).digest()
    elif not info:
        raise TinyPkiError("Expected a non-empty info label, or None for the legacy derivation")
    else:
        digest = HKDF(algorithm=SHA256(), length=32, salt=None, info=info).derive(secret.encode())
    return base64.urlsafe_b64encode(digest)


def _derive_scrypt_fernet_key(secret: str, salt: bytes, *, n: int, r: int, p: int) -> bytes:
    digest = Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(secret.encode())
    return base64.urlsafe_b64encode(digest)


def _require_secret(secret: str) -> None:
    if not secret or not secret.strip():
        raise TinyPkiError("Expected a non-empty secret")


def _require_strong_secret(secret: str) -> None:
    _require_secret(secret)
    if len(secret) < MIN_SECRET_LENGTH:
        raise TinyPkiError(f"Expected a secret of at least {MIN_SECRET_LENGTH} characters, got {len(secret)}")


_SCRYPT_PROFILE = (2**17, 8, 1)
_SUPPORTED_SCRYPT_PROFILES = frozenset({_SCRYPT_PROFILE})
_SCRYPT_PARAMS = struct.Struct(">III")
_SCRYPT_SALT_SIZE = 16
