"""TinyPkiError: every library input/policy rejection, still a ValueError (issue #57)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from hamcrest import assert_that, contains_string, instance_of, is_, is_not

from tiny_pki import (
    TinyPkiError,
    check_certificate,
    generate_ca_certificate,
    generate_client_certificate,
    generate_crl,
    generate_pkcs12,
    generate_server_certificate,
)
from tiny_pki.names import normalize_san_entries, normalize_subject_attribute
from tiny_pki.secrets import encrypt_private_key

_CA_CERT, _CA_KEY = generate_ca_certificate("Errors CA", key_size=2048)
_CLIENT_CERT, _CLIENT_KEY = generate_client_certificate(_CA_CERT, _CA_KEY, "alice", key_size=2048)
_EC_KEY = ec.generate_private_key(ec.SECP256R1()).private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
)


@pytest.mark.parametrize(
    "call",
    [
        pytest.param(lambda: generate_ca_certificate(key_size=1024), id="issue-key-size"),
        pytest.param(
            lambda: generate_server_certificate(_CA_CERT, _CA_KEY, "api", ["https://api.home"], key_size=2048),
            id="issue-san-url",
        ),
        pytest.param(
            lambda: generate_client_certificate(
                _CA_CERT, _CA_KEY, "bob", validity_days=36500, key_size=2048, allow_long_validity=True
            ),
            id="issue-outlives-ca",
        ),
        pytest.param(lambda: generate_crl(_CA_CERT, _CA_KEY, [], validity_days=0), id="revoke-validity"),
        pytest.param(
            lambda: generate_pkcs12(_CLIENT_CERT, _CLIENT_KEY, _CA_CERT, "alice", b"short"), id="bundle-password"
        ),
        pytest.param(lambda: normalize_san_entries([]), id="names-empty-san"),
        pytest.param(lambda: normalize_subject_attribute("", "common_name", max_length=64), id="names-empty-cn"),
        pytest.param(lambda: encrypt_private_key(_CLIENT_KEY, "too-short"), id="secrets-weak-secret"),
        pytest.param(lambda: check_certificate(_CLIENT_CERT, now=datetime(2026, 1, 1)), id="check-naive-now"),
        pytest.param(lambda: generate_crl(_CA_CERT, _EC_KEY, []), id="rsa-not-rsa"),
    ],
)
def test_rejections_raise_tiny_pki_error(call: Callable[[], object]) -> None:
    with pytest.raises(TinyPkiError) as raised:
        call()
    assert_that(raised.value, is_(instance_of(ValueError)))
    assert_that(str(raised.value), contains_string("Expected"))
    assert_that(str(raised.value), is_not(contains_string("PRIVATE KEY")))
