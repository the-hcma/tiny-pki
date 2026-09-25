"""CRL nextUpdate window and revocation dates (issue #63)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import cast

import pytest
import time_machine
from cryptography import x509
from hamcrest import assert_that, equal_to, has_length, is_, not_none

from tiny_pki import CLOCK_SKEW_BACKDATE, generate_ca_certificate, generate_crl


@pytest.mark.parametrize("validity_days", [None, 1, 7, 90])
def test_next_update_is_validity_days_from_now(validity_days: int | None) -> None:
    with time_machine.travel(_NOW, tick=False):
        if validity_days is None:
            crl_pem = generate_crl(_CA_CERT, _CA_KEY, [])
        else:
            crl_pem = generate_crl(_CA_CERT, _CA_KEY, [], validity_days=validity_days)
    crl = x509.load_pem_x509_crl(crl_pem)
    assert_that(crl.last_update_utc, equal_to(_NOW - CLOCK_SKEW_BACKDATE))
    assert_that(crl.next_update_utc, is_(not_none()))
    assert_that(crl.next_update_utc, equal_to(_NOW + timedelta(days=validity_days or 30)))


def test_revocation_dates_round_trip() -> None:
    serial_to_revoked_at = {
        0x1: datetime(2025, 12, 31, 23, 59, 59, tzinfo=UTC),
        0xABCDEF: datetime(2026, 2, 14, 8, 30, tzinfo=UTC),
        2**150 + 7: _NOW - timedelta(seconds=1),
    }
    with time_machine.travel(_NOW, tick=False):
        crl_pem = generate_crl(_CA_CERT, _CA_KEY, list(serial_to_revoked_at.items()))
    crl = x509.load_pem_x509_crl(crl_pem)
    assert_that(list(crl), has_length(len(serial_to_revoked_at)))
    for serial, revoked_at in serial_to_revoked_at.items():
        entry = crl.get_revoked_certificate_by_serial_number(serial)
        assert_that(entry, is_(not_none()))
        assert_that(cast(x509.RevokedCertificate, entry).revocation_date_utc, equal_to(revoked_at))


_CA_CERT, _CA_KEY = generate_ca_certificate("CRL Window CA", key_size=2048)
_NOW = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
