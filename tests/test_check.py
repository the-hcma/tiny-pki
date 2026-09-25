"""Expiry and validity checks for certificates and CRLs (issue #48)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import math
import random
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
import time_machine
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from hamcrest import (
    assert_that,
    calling,
    contains_string,
    equal_to,
    has_item,
    is_,
    none,
    not_none,
    raises,
)
from pytest import CaptureFixture

from tiny_pki import (
    MAX_CA_WARNING_DAYS,
    MAX_LEAF_WARNING_DAYS,
    CertificateKind,
    CertificateStatus,
    Status,
    TinyPkiError,
    check_certificate,
    check_crl,
    default_warning_window,
    generate_ca_certificate,
    generate_client_certificate,
    generate_crl,
    generate_server_certificate,
    get_certificate_serial_number,
    worst_status,
)
from tiny_pki._rsa import load_rsa_private_key
from tiny_pki.cli.main import main

_CA = generate_ca_certificate("Check CA", key_size=2048)
_OTHER_CA = generate_ca_certificate("Other CA", key_size=2048)
_SERVER = generate_server_certificate(_CA[0], _CA[1], "api.home", ["api.home"], key_size=2048)
_CLIENT = generate_client_certificate(_CA[0], _CA[1], "alice", key_size=2048)


def test_boundaries_at_the_cutoff_and_expiry() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    end = start + timedelta(days=90)
    cert = _leaf(start, end)
    tick = timedelta(microseconds=1)
    now = start + timedelta(days=10)
    assert_that(_status(cert, now=now, by=end), equal_to(Status.EXPIRING))
    assert_that(_status(cert, now=now, by=end - tick), equal_to(Status.OK))
    assert_that(_status(cert, now=end - tick, within=timedelta(0)), equal_to(Status.OK))
    assert_that(_status(cert, now=end, within=timedelta(0)), equal_to(Status.EXPIRED))
    assert_that(_status(cert, now=start - tick), equal_to(Status.NOT_YET_VALID))
    assert_that(_status(cert, now=start), equal_to(Status.OK))


def test_ca_expiring_first_shortens_effective_validity() -> None:
    ca_end = datetime(2026, 6, 1, tzinfo=UTC)
    ca_cert, ca_key = _custom_ca(datetime(2026, 1, 1, tzinfo=UTC), ca_end)
    leaf = _leaf(datetime(2026, 5, 1, tzinfo=UTC), datetime(2026, 12, 1, tzinfo=UTC), ca=(ca_cert, ca_key))
    now = datetime(2026, 5, 20, tzinfo=UTC)
    alone = check_certificate(leaf, now=now)
    with_ca = check_certificate(leaf, now=now, ca_cert_pem=ca_cert)
    assert_that(alone.status, equal_to(Status.OK))
    assert_that(with_ca.status, equal_to(Status.EXPIRING))
    assert_that(with_ca.not_after, equal_to(ca_end))
    assert_that(with_ca.reasons, has_item(contains_string("CA expires first")))
    assert_that(check_certificate(leaf, now=ca_end, ca_cert_pem=ca_cert).status, equal_to(Status.EXPIRED))


def test_check_crl_freshness_and_trust() -> None:
    crl = generate_crl(_CA[0], _CA[1], [], validity_days=30, crl_number=7)
    fresh = check_crl(crl, ca_cert_pem=_CA[0])
    assert_that(fresh.kind, equal_to("crl"))
    assert_that(fresh.status, equal_to(Status.OK))
    assert_that(fresh.serial_number, equal_to(7))
    assert_that(fresh.subject, equal_to("Check CA"))
    assert_that(fresh.days_remaining, equal_to(29))
    assert_that(fresh.not_after, is_(not_none()))
    next_update = cast(datetime, fresh.not_after)
    assert_that(check_crl(crl, now=next_update - timedelta(days=9)).status, equal_to(Status.EXPIRING))
    assert_that(check_crl(crl, now=next_update).status, equal_to(Status.EXPIRED))
    assert_that(check_crl(crl, ca_cert_pem=_OTHER_CA[0]).status, equal_to(Status.UNTRUSTED))


def test_cli_inspect_reports_revoked_identity(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    store = tmp_path / "ca"
    _cli(store, "init", "--key-size", "2048")
    _cli(store, "create", "client", "bob", "--key-size", "2048")
    capsys.readouterr()
    _cli(store, "inspect", "bob")
    assert_that(capsys.readouterr().out, contains_string("valid, 396 days left"))
    _cli(store, "revoke", "bob")
    capsys.readouterr()
    _cli(store, "inspect", "bob")
    out = capsys.readouterr().out
    assert_that(out, contains_string("(revoked)"))
    assert_that(out, contains_string("revoked on"))


def test_ca_cert_pem_must_be_a_ca() -> None:
    crl = generate_crl(_CA[0], _CA[1], [])
    message = re.escape("Expected a CA certificate (BasicConstraints ca=True) for ca_cert_pem, got api.home")
    assert_that(calling(check_certificate).with_args(_CLIENT[0], ca_cert_pem=_SERVER[0]), raises(TinyPkiError, message))
    assert_that(calling(check_crl).with_args(crl, ca_cert_pem=_SERVER[0]), raises(TinyPkiError, message))


def test_cli_inspect_shows_expiring_and_expired(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    cert = tmp_path / "leaf.pem"
    cert.write_bytes(_leaf(start, start + timedelta(days=90)))
    for offset, expected in [
        (timedelta(days=89), "expiring in 1 day"),
        (timedelta(days=85), "expiring in 5 days"),
        (timedelta(days=91), "expired 1 day ago"),
        (timedelta(days=100), "expired 10 days ago"),
    ]:
        with time_machine.travel(start + offset, tick=False):
            main(["--color", "never", "inspect", str(cert)])
        assert_that(capsys.readouterr().out, contains_string(expected))


def test_crl_without_next_update_or_crl_number(monkeypatch: pytest.MonkeyPatch) -> None:
    key = load_rsa_private_key(_CA[1])
    now = datetime.now(UTC)
    bare = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(x509.load_pem_x509_certificate(_CA[0]).subject)
        .last_update(now - timedelta(minutes=5))
        .next_update(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
    )
    assert_that(check_crl(bare, ca_cert_pem=_CA[0]).serial_number, is_(none()))
    load = x509.load_pem_x509_crl

    def load_without_next_update(data: bytes) -> _WithoutNextUpdate:
        return _WithoutNextUpdate(load(data))

    monkeypatch.setattr(x509, "load_pem_x509_crl", load_without_next_update)
    result = check_crl(bare, ca_cert_pem=_CA[0])
    assert_that(result.status, equal_to(Status.OK))
    assert_that(result.not_after, is_(none()))
    assert_that(result.days_remaining, is_(none()))
    assert_that(result.reasons, equal_to(("no nextUpdate",)))


def test_cli_inspect_tolerates_missing_ca_key_and_foreign_crl(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    store = tmp_path / "ca"
    _cli(store, "init", "--key-size", "2048")
    _cli(store, "create", "client", "carol", "--key-size", "2048")
    (store / "ca" / "crl.pem").write_bytes(generate_crl(_OTHER_CA[0], _OTHER_CA[1], []))
    (store / "ca" / "ca.key").unlink()
    capsys.readouterr()
    _cli(store, "inspect", "carol")
    captured = capsys.readouterr()
    assert_that(captured.out, contains_string("valid, 396 days left"))
    assert_that(captured.err, contains_string("ignoring the store CRL"))
    (store / "ca" / "crl.pem").write_bytes(b"truncated")
    _cli(store, "inspect", "carol")
    captured = capsys.readouterr()
    assert_that(captured.out, contains_string("valid, 396 days left"))
    assert_that(captured.err, contains_string("ignoring the store CRL"))
    (store / "ca" / "ca.crt").write_bytes(_CLIENT[0])
    _cli(store, "inspect", "carol")
    captured = capsys.readouterr()
    assert_that(captured.out, contains_string("valid, 396 days left"))
    assert_that(captured.err, contains_string("ignoring the store CA and CRL: Expected a CA certificate"))


def test_crl_requires_a_ca_and_a_matching_signature() -> None:
    crl = generate_crl(_CA[0], _CA[1], [])
    assert_that(
        calling(check_certificate).with_args(_CLIENT[0], crl_pem=crl),
        raises(TinyPkiError, "Expected ca_cert_pem with crl_pem"),
    )
    assert_that(
        calling(check_certificate).with_args(_CLIENT[0], ca_cert_pem=_OTHER_CA[0], crl_pem=crl),
        raises(TinyPkiError, "Expected a CRL signed by Other CA"),
    )


@pytest.mark.parametrize(
    ("kind", "lifetime_days", "expected_days"),
    [
        ("server", 90, 30),
        ("server", 30, 10),
        ("client", 397, MAX_LEAF_WARNING_DAYS),
        ("unknown", 600, MAX_LEAF_WARNING_DAYS),
        ("ca", 3650, MAX_CA_WARNING_DAYS),
        ("ca", 300, 100),
        ("crl", 30, 10),
        ("crl", 3000, 1000),
    ],
)
def test_default_warning_window(kind: CertificateKind, lifetime_days: int, expected_days: int) -> None:
    window = default_warning_window(kind, timedelta(days=lifetime_days))
    assert_that(window, equal_to(timedelta(days=expected_days)))


def test_default_window_applies_without_within_or_by() -> None:
    issued = check_certificate(_SERVER[0])
    thirty_days_before_expiry = cast(datetime, issued.not_after) - timedelta(days=30)
    assert_that(_status(_SERVER[0], now=thirty_days_before_expiry - timedelta(seconds=1)), equal_to(Status.OK))
    assert_that(_status(_SERVER[0], now=thirty_days_before_expiry), equal_to(Status.EXPIRING))


def test_earlier_of_within_and_by_wins() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    cert = _leaf(now - timedelta(days=1), now + timedelta(days=20))
    far = now + timedelta(days=60)
    assert_that(check_certificate(cert, now=now, within=timedelta(days=10), by=far).status, equal_to(Status.OK))
    result = check_certificate(cert, now=now, within=timedelta(days=30), by=now + timedelta(days=5))
    assert_that(result.cutoff, equal_to(now + timedelta(days=5)))


def test_kinds_and_labels() -> None:
    server = check_certificate(_SERVER[0], ca_cert_pem=_CA[0])
    assert_that(server.kind, equal_to("server"))
    assert_that(server.subject, equal_to("api.home"))
    assert_that(server.issuer, equal_to("Check CA"))
    assert_that(server.serial_number, equal_to(get_certificate_serial_number(_SERVER[0])))
    assert_that(server.status, equal_to(Status.OK))
    assert_that(check_certificate(_CLIENT[0]).kind, equal_to("client"))
    assert_that(check_certificate(_CA[0], ca_cert_pem=_CA[0]).kind, equal_to("ca"))
    start = datetime(2026, 1, 1, tzinfo=UTC)
    no_eku = _leaf(start, start + timedelta(days=10), eku=None, common_name=None)
    result = check_certificate(no_eku, now=start)
    assert_that(result.kind, equal_to("unknown"))
    assert_that(result.subject, equal_to("O=No CN"))


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"now": datetime(2026, 1, 1)}, "timezone-aware now"),  # noqa: DTZ001
        ({"by": datetime(2026, 1, 1)}, "timezone-aware by"),  # noqa: DTZ001
        ({"within": timedelta(days=-1)}, "non-negative within"),
    ],
)
def test_rejects_invalid_arguments(kwargs: dict[str, object], message: str) -> None:
    assert_that(calling(check_certificate).with_args(_SERVER[0], **kwargs), raises(TinyPkiError, message))


def test_randomized_statuses_match_reference() -> None:
    rng = random.Random(48)
    start = datetime(2026, 1, 1, tzinfo=UTC)
    for _ in range(40):
        not_before = start + timedelta(days=rng.randint(-400, 400))
        not_after = not_before + timedelta(days=rng.randint(1, 900), seconds=rng.randint(0, 86399))
        cert = _leaf(not_before, not_after)
        now = start + timedelta(days=rng.randint(-500, 1400), seconds=rng.randint(0, 86399))
        within = timedelta(days=rng.randint(0, 120)) if rng.random() < 0.7 else None
        result = check_certificate(cert, now=now, within=within)
        window = within if within is not None else min((not_after - not_before) / 3, timedelta(days=30))
        if now < not_before:
            expected = Status.NOT_YET_VALID
        elif now >= not_after:
            expected = Status.EXPIRED
        elif not_after <= now + window:
            expected = Status.EXPIRING
        else:
            expected = Status.OK
        assert_that(result.status, equal_to(expected))
        assert_that(result.days_remaining, equal_to(math.floor((not_after - now) / timedelta(days=1))))


def test_revoked_and_untrusted() -> None:
    crl = generate_crl(_CA[0], _CA[1], [(get_certificate_serial_number(_CLIENT[0]), datetime.now(UTC))])
    revoked = check_certificate(_CLIENT[0], ca_cert_pem=_CA[0], crl_pem=crl)
    assert_that(revoked.status, equal_to(Status.REVOKED))
    assert_that(revoked.reasons, has_item(contains_string("revoked on")))
    assert_that(check_certificate(_SERVER[0], ca_cert_pem=_CA[0], crl_pem=crl).status, equal_to(Status.OK))
    untrusted = check_certificate(_SERVER[0], ca_cert_pem=_OTHER_CA[0])
    assert_that(untrusted.status, equal_to(Status.UNTRUSTED))
    assert_that(untrusted.reasons, equal_to(("not issued by Other CA",)))


def test_severity_follows_declaration_order() -> None:
    assert_that([s.severity for s in Status], equal_to(list(range(len(Status)))))
    assert_that(
        [s.value for s in Status],
        equal_to(["ok", "expiring", "not_yet_valid", "expired", "revoked", "untrusted"]),
    )


def test_uses_current_time_by_default() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    cert = _leaf(start, start + timedelta(days=90))
    with time_machine.travel(start + timedelta(days=89), tick=False):
        result = check_certificate(cert)
    assert_that(result.status, equal_to(Status.EXPIRING))
    assert_that(result.days_remaining, equal_to(1))


def test_worst_status() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    results = [
        check_certificate(_leaf(now - timedelta(days=1), now + timedelta(days=100)), now=now),
        check_certificate(_leaf(now - timedelta(days=1), now + timedelta(days=5)), now=now, within=timedelta(days=7)),
    ]
    assert_that(worst_status(results), equal_to(Status.EXPIRING))
    assert_that(worst_status([]), equal_to(Status.OK))
    assert_that(worst_status([*results, _expired(now)]), equal_to(Status.EXPIRED))


class _WithoutNextUpdate:
    """A loaded CRL that reports no ``nextUpdate`` (``cryptography`` cannot build one)."""

    next_update_utc = None

    def __init__(self, crl: x509.CertificateRevocationList) -> None:
        self._crl = crl

    def __getattr__(self, name: str) -> object:
        return getattr(self._crl, name)


def _cli(store: Path, *words: str) -> None:
    main(["--store", str(store), "--color", "never", *words])


def _custom_ca(not_before: datetime, not_after: datetime) -> tuple[bytes, bytes]:
    key = load_rsa_private_key(_CA[1])
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Short CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM), _CA[1]


def _expired(now: datetime) -> CertificateStatus:
    return check_certificate(_leaf(now - timedelta(days=10), now - timedelta(days=1)), now=now)


def _leaf(
    not_before: datetime,
    not_after: datetime,
    *,
    ca: tuple[bytes, bytes] = _CA,
    eku: x509.ObjectIdentifier | None = ExtendedKeyUsageOID.SERVER_AUTH,
    common_name: str | None = "leaf.home",
) -> bytes:
    ca_cert = x509.load_pem_x509_certificate(ca[0])
    ca_key = load_rsa_private_key(ca[1])
    attributes = [x509.NameAttribute(NameOID.ORGANIZATION_NAME, "No CN")]
    if common_name is not None:
        attributes = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name(attributes))
        .issuer_name(ca_cert.subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if eku is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
    return builder.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


def _status(cert_pem: bytes, *, now: datetime, within: timedelta | None = None, by: datetime | None = None) -> Status:
    return check_certificate(cert_pem, now=now, within=within, by=by).status
