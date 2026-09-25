"""Leaf certificate extension profile for server and client issuance (issue #61)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

from collections.abc import Callable
from typing import cast

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from hamcrest import assert_that, calling, equal_to, is_, raises

from tiny_pki import (
    TinyPkiError,
    generate_ca_certificate,
    generate_client_certificate,
    generate_server_certificate,
)

type Issue = Callable[[int], tuple[bytes, bytes]]

_CA_CERT, _CA_KEY = generate_ca_certificate("Profile CA", key_size=2048)
_CA_X509 = x509.load_pem_x509_certificate(_CA_CERT)
_ISSUERS: dict[str, Issue] = {
    "client": lambda key_size: generate_client_certificate(_CA_CERT, _CA_KEY, "alice", key_size=key_size),
    "server": lambda key_size: generate_server_certificate(
        _CA_CERT, _CA_KEY, "api.home", ["api.home"], key_size=key_size
    ),
}
_KINDS = ("client", "server")
_LEAVES = {kind: x509.load_pem_x509_certificate(issue(2048)[0]) for kind, issue in _ISSUERS.items()}


@pytest.mark.parametrize("kind", _KINDS)
def test_basic_constraints_is_critical_end_entity(kind: str) -> None:
    extension = _LEAVES[kind].extensions.get_extension_for_class(x509.BasicConstraints)
    assert_that(extension.critical, is_(True))
    assert_that(extension.value, equal_to(x509.BasicConstraints(ca=False, path_length=None)))


@pytest.mark.parametrize("kind", _KINDS)
def test_key_identifiers_chain_to_the_ca(kind: str) -> None:
    leaf = _LEAVES[kind]
    ski = leaf.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    aki = leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    ca_ski = _CA_X509.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    assert_that(ski.critical, is_(False))
    assert_that(ski.value, equal_to(x509.SubjectKeyIdentifier.from_public_key(_rsa_public_key(leaf))))
    assert_that(aki.critical, is_(False))
    assert_that(aki.value.key_identifier, equal_to(ca_ski.digest))


@pytest.mark.parametrize("kind", _KINDS)
def test_key_size_must_be_allowed_and_is_honored(kind: str) -> None:
    for bad in (1024, 2047, 8192):
        assert_that(calling(_ISSUERS[kind]).with_args(bad), raises(TinyPkiError, "Expected key_size in"))
    assert_that(_rsa_public_key(_LEAVES[kind]).key_size, equal_to(2048))


@pytest.mark.parametrize("kind", _KINDS)
def test_key_usage_is_critical_signature_and_encipherment_only(kind: str) -> None:
    extension = _LEAVES[kind].extensions.get_extension_for_class(x509.KeyUsage)
    assert_that(extension.critical, is_(True))
    assert_that(
        extension.value,
        equal_to(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            )
        ),
    )


def _rsa_public_key(cert: x509.Certificate) -> RSAPublicKey:
    return cast(RSAPublicKey, cert.public_key())
