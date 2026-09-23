"""Tests for optional Fernet private-key helpers."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken
from hamcrest import assert_that, calling, equal_to, is_not, raises

from tiny_pki import generate_ca_certificate
from tiny_pki.secrets import (
    decrypt_private_key,
    derive_fernet_key,
    encrypt_private_key,
    reencrypt_private_key,
)


def test_derive_fernet_key_is_deterministic_and_fernet_valid() -> None:
    key = derive_fernet_key("dev-secret")
    assert_that(key, equal_to(derive_fernet_key("dev-secret")))
    token = Fernet(key).encrypt(b"probe")
    assert_that(Fernet(key).decrypt(token), equal_to(b"probe"))


def test_derive_fernet_key_uses_verbatim_secret() -> None:
    # Whitespace is rejected only when the secret is empty after strip; otherwise
    # the raw secret (including padding spaces) is hashed as-is.
    assert_that(derive_fernet_key(" s "), is_not(equal_to(derive_fernet_key("s"))))


def test_empty_pem_data_rejected() -> None:
    assert_that(
        calling(encrypt_private_key).with_args(b"", "dev-secret"),
        raises(ValueError, "non-empty pem_data"),
    )


def test_empty_secret_rejected() -> None:
    assert_that(
        calling(encrypt_private_key).with_args(b"pem", "  "),
        raises(ValueError, "non-empty secret"),
    )


def test_encrypt_decrypt_roundtrip() -> None:
    _, key_pem = generate_ca_certificate(key_size=2048)
    encrypted = encrypt_private_key(key_pem, "dev-secret")
    assert_that(encrypted, is_not(equal_to(key_pem)))
    assert_that(decrypt_private_key(encrypted, "dev-secret"), equal_to(key_pem))


def test_reencrypt_roundtrip() -> None:
    _, key_pem = generate_ca_certificate(key_size=2048)
    encrypted = encrypt_private_key(key_pem, "old-secret")
    re_encrypted = reencrypt_private_key(encrypted, "old-secret", "new-secret")
    assert_that(decrypt_private_key(re_encrypted, "new-secret"), equal_to(key_pem))


def test_wrong_secret_fails() -> None:
    _, key_pem = generate_ca_certificate(key_size=2048)
    encrypted = encrypt_private_key(key_pem, "correct")
    assert_that(
        calling(decrypt_private_key).with_args(encrypted, "wrong"),
        raises(InvalidToken),
    )
