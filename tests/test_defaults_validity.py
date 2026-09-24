"""Validity, key-size, and clock-skew defaults (issue #32)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import warnings
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from hamcrest import (
    assert_that,
    calling,
    contains_string,
    equal_to,
    has_length,
    less_than_or_equal_to,
    not_none,
    raises,
)
from pytest import CaptureFixture
from pytest import raises as pytest_raises

from tiny_pki import (
    APPLE_MAX_SERVER_VALIDITY_DAYS,
    CLOCK_SKEW_BACKDATE,
    DEFAULT_CLIENT_VALIDITY_DAYS,
    DEFAULT_LEAF_KEY_SIZE,
    DEFAULT_SERVER_VALIDITY_DAYS,
    MAX_CLIENT_VALIDITY_DAYS,
    MAX_SERVER_VALIDITY_DAYS,
    TinyPkiWarning,
    generate_ca_certificate,
    generate_client_certificate,
    generate_crl,
    generate_server_certificate,
)
from tiny_pki.cli.main import main
from tiny_pki.store import CertificateStore, IssuedCertificate

_CA = generate_ca_certificate("Defaults CA", key_size=2048)


def test_backdates_ca_leaf_and_crl_for_clock_skew() -> None:
    ca_cert, ca_key = _CA
    client_pem, _ = generate_client_certificate(ca_cert, ca_key, "alice", key_size=2048)
    crl = x509.load_pem_x509_crl(generate_crl(ca_cert, ca_key, []))
    limit = datetime.now(UTC) - CLOCK_SKEW_BACKDATE + timedelta(seconds=5)
    for cert_pem in (ca_cert, client_pem):
        not_before = x509.load_pem_x509_certificate(cert_pem).not_valid_before_utc
        assert_that(not_before, less_than_or_equal_to(limit))
    assert_that(crl.last_update_utc, less_than_or_equal_to(limit))


def test_cli_create_server_defaults_and_long_validity_override(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    store = tmp_path / "ca"
    _cli(store, "init", "--key-size", "2048")
    capsys.readouterr()

    _cli(store, "create", "server", "api.home", "--key-size", "2048")
    cs = CertificateStore(store)
    entry = cs.get_certificate("api.home")
    assert_that(entry, not_none())
    cert = x509.load_pem_x509_certificate(cs.read_certificate_pem(cast(IssuedCertificate, entry)))
    assert_that(_lifetime_days(cert), equal_to(DEFAULT_SERVER_VALIDITY_DAYS))
    capsys.readouterr()

    with pytest_raises(SystemExit):
        _cli(store, "create", "server", "long.home", "--key-size", "2048", "--days", "400")
    assert_that(capsys.readouterr().err, contains_string("--allow-long-validity"))

    days = str(APPLE_MAX_SERVER_VALIDITY_DAYS + 1)
    _cli(store, "create", "server", "apple.home", "--allow-long-validity", "--days", days, "--key-size", "2048")
    captured = capsys.readouterr()
    assert_that(captured.out, contains_string("issued server apple.home"))
    assert_that(captured.err, contains_string("Apple platforms will reject it"))


def test_client_cap_and_override() -> None:
    ca_cert, ca_key = _CA
    too_long = MAX_CLIENT_VALIDITY_DAYS + 1
    assert_that(
        calling(generate_client_certificate).with_args(ca_cert, ca_key, "alice", key_size=2048, validity_days=too_long),
        raises(ValueError, f"validity_days <= {MAX_CLIENT_VALIDITY_DAYS} for client"),
    )
    cert_pem, _ = generate_client_certificate(
        ca_cert, ca_key, "alice", key_size=2048, validity_days=too_long, allow_long_validity=True
    )
    assert_that(_lifetime_days(x509.load_pem_x509_certificate(cert_pem)), equal_to(too_long))


def test_default_leaf_key_size() -> None:
    ca_cert, ca_key = _CA
    cert_pem, _ = generate_client_certificate(ca_cert, ca_key, "alice")
    public_key = cast(RSAPublicKey, x509.load_pem_x509_certificate(cert_pem).public_key())
    assert_that(public_key.key_size, equal_to(DEFAULT_LEAF_KEY_SIZE))


def test_default_leaf_validity() -> None:
    ca_cert, ca_key = _CA
    client_pem, _ = generate_client_certificate(ca_cert, ca_key, "alice", key_size=2048)
    server_pem, _ = generate_server_certificate(ca_cert, ca_key, "api.home", ["api.home"], key_size=2048)
    assert_that(_lifetime_days(x509.load_pem_x509_certificate(client_pem)), equal_to(DEFAULT_CLIENT_VALIDITY_DAYS))
    assert_that(_lifetime_days(x509.load_pem_x509_certificate(server_pem)), equal_to(DEFAULT_SERVER_VALIDITY_DAYS))


def test_leaf_cannot_outlive_ca() -> None:
    short_ca, short_key = generate_ca_certificate("Short CA", key_size=2048, validity_days=30)
    for issue, extra in (
        (generate_client_certificate, ("alice",)),
        (generate_server_certificate, ("api.home", ["api.home"])),
    ):
        assert_that(
            calling(issue).with_args(short_ca, short_key, *extra, key_size=2048, validity_days=31),
            raises(ValueError, r"use validity_days <= (29|30) or renew the CA"),
        )
    cert_pem, _ = generate_client_certificate(short_ca, short_key, "alice", key_size=2048, validity_days=29)
    assert_that(_lifetime_days(x509.load_pem_x509_certificate(cert_pem)), equal_to(29))


def test_server_cap_override_and_apple_warning() -> None:
    ca_cert, ca_key = _CA
    too_long = MAX_SERVER_VALIDITY_DAYS + 1
    assert_that(
        calling(generate_server_certificate).with_args(
            ca_cert, ca_key, "api.home", ["api.home"], key_size=2048, validity_days=too_long
        ),
        raises(ValueError, "allow_long_validity=True"),
    )
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        generate_server_certificate(
            ca_cert, ca_key, "api.home", ["api.home"], key_size=2048, validity_days=too_long, allow_long_validity=True
        )
        at_apple_limit, _ = generate_server_certificate(
            ca_cert,
            ca_key,
            "api.home",
            ["api.home"],
            key_size=2048,
            validity_days=APPLE_MAX_SERVER_VALIDITY_DAYS,
            allow_long_validity=True,
        )
    assert_that(caught, has_length(0))
    assert_that(
        _lifetime_days(x509.load_pem_x509_certificate(at_apple_limit)), equal_to(APPLE_MAX_SERVER_VALIDITY_DAYS)
    )

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        generate_server_certificate(
            ca_cert,
            ca_key,
            "api.home",
            ["api.home"],
            key_size=2048,
            validity_days=APPLE_MAX_SERVER_VALIDITY_DAYS + 1,
            allow_long_validity=True,
        )
    assert_that(caught, has_length(1))
    assert_that(caught[0].category, equal_to(TinyPkiWarning))
    assert_that(caught[0].filename, contains_string("test_defaults_validity"))


def _cli(store: Path, *words: str) -> None:
    main(["--store", str(store), "--color", "never", *words])


def _lifetime_days(cert: x509.Certificate) -> int:
    span = cert.not_valid_after_utc - cert.not_valid_before_utc
    assert_that(span.seconds, equal_to(0))
    return span.days
