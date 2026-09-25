"""Tests for optional Fernet private-key helpers."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken
from hamcrest import assert_that, calling, equal_to, is_not, raises

from tiny_pki import TinyPkiError, generate_ca_certificate
from tiny_pki.secrets import (
    MIN_SECRET_LENGTH,
    decrypt_private_key,
    derive_fernet_key,
    encrypt_private_key,
    reencrypt_private_key,
)

_NEW = "n" * MIN_SECRET_LENGTH
_OLD = "o" * MIN_SECRET_LENGTH
_OTHER = "x" * MIN_SECRET_LENGTH
_SECRET = "s" * MIN_SECRET_LENGTH


def test_derive_fernet_key_is_deterministic_and_fernet_valid() -> None:
    key = derive_fernet_key(_SECRET)
    assert_that(key, equal_to(derive_fernet_key(_SECRET)))
    token = Fernet(key).encrypt(b"probe")
    assert_that(Fernet(key).decrypt(token), equal_to(b"probe"))


def test_derive_fernet_key_uses_verbatim_secret() -> None:
    # Whitespace is rejected only when the secret is empty after strip; otherwise
    # the raw secret (including padding spaces) is hashed as-is.
    assert_that(derive_fernet_key(f" {_SECRET} "), is_not(equal_to(derive_fernet_key(_SECRET))))


def test_empty_pem_data_rejected() -> None:
    assert_that(
        calling(encrypt_private_key).with_args(b"", _SECRET),
        raises(TinyPkiError, "non-empty pem_data"),
    )


def test_empty_secret_rejected() -> None:
    assert_that(
        calling(encrypt_private_key).with_args(b"pem", "  "),
        raises(TinyPkiError, "non-empty secret"),
    )


def test_encrypt_decrypt_roundtrip() -> None:
    _, key_pem = generate_ca_certificate(key_size=2048)
    encrypted = encrypt_private_key(key_pem, _SECRET)
    assert_that(encrypted, is_not(equal_to(key_pem)))
    assert_that(decrypt_private_key(encrypted, _SECRET), equal_to(key_pem))


def test_reencrypt_rotates_off_a_short_secret() -> None:
    _, key_pem = generate_ca_certificate(key_size=2048)
    legacy_token = Fernet(_legacy_key("short")).encrypt(key_pem)
    rotated = reencrypt_private_key(legacy_token, "short", _NEW)
    assert_that(decrypt_private_key(rotated, _NEW), equal_to(key_pem))
    assert_that(
        calling(reencrypt_private_key).with_args(rotated, _NEW, "short"),
        raises(TinyPkiError, f"at least {MIN_SECRET_LENGTH} characters, got 5"),
    )


def test_reencrypt_roundtrip() -> None:
    _, key_pem = generate_ca_certificate(key_size=2048)
    encrypted = encrypt_private_key(key_pem, _OLD)
    re_encrypted = reencrypt_private_key(encrypted, _OLD, _NEW)
    assert_that(decrypt_private_key(re_encrypted, _NEW), equal_to(key_pem))


def test_short_secret_rejected() -> None:
    short = "s" * (MIN_SECRET_LENGTH - 1)
    for fn, args in ((derive_fernet_key, (short,)), (encrypt_private_key, (b"pem", short))):
        assert_that(
            calling(fn).with_args(*args),
            raises(TinyPkiError, f"at least {MIN_SECRET_LENGTH} characters, got {len(short)}"),
        )


def test_wrong_secret_fails() -> None:
    _, key_pem = generate_ca_certificate(key_size=2048)
    encrypted = encrypt_private_key(key_pem, _SECRET)
    assert_that(
        calling(decrypt_private_key).with_args(encrypted, _OTHER),
        raises(InvalidToken),
    )


def _legacy_key(secret: str) -> bytes:
    return base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())
