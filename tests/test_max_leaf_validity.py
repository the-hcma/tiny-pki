"""max_leaf_validity_days: the largest validity issuance accepts right now (issue #58)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import math
import random
from datetime import UTC, datetime, timedelta
from typing import Literal

import time_machine
from hamcrest import assert_that, calling, equal_to, raises

from tiny_pki import (
    MAX_CLIENT_VALIDITY_DAYS,
    MAX_SERVER_VALIDITY_DAYS,
    TinyPkiError,
    generate_ca_certificate,
    generate_client_certificate,
    generate_server_certificate,
    max_leaf_validity_days,
)


def test_caps_apply_unless_long_validity_is_allowed() -> None:
    with time_machine.travel(_START, tick=False):
        ca_cert, _ = generate_ca_certificate("Long CA", key_size=2048)
        assert_that(max_leaf_validity_days(ca_cert), equal_to(MAX_SERVER_VALIDITY_DAYS))
        assert_that(max_leaf_validity_days(ca_cert, kind="client"), equal_to(MAX_CLIENT_VALIDITY_DAYS))
        assert_that(max_leaf_validity_days(ca_cert, allow_long_validity=True), equal_to(3650))
        assert_that(max_leaf_validity_days(ca_cert, kind="client", allow_long_validity=True), equal_to(3650))


def test_expired_ca_allows_nothing() -> None:
    with time_machine.travel(_START, tick=False):
        ca_cert, _ = generate_ca_certificate("Short CA", key_size=2048, validity_days=30)
    for offset in (timedelta(days=30), timedelta(days=30) - timedelta(minutes=5), timedelta(days=400)):
        with time_machine.travel(_START + offset, tick=False):
            assert_that(max_leaf_validity_days(ca_cert, allow_long_validity=True), equal_to(0))


def test_rejects_unknown_kind() -> None:
    ca_cert, _ = generate_ca_certificate("Kind CA", key_size=2048)
    assert_that(
        calling(max_leaf_validity_days).with_args(ca_cert, kind="ca"),
        raises(TinyPkiError, "Expected kind 'client' or 'server', got 'ca'"),
    )


def test_returned_value_issues_and_one_more_fails() -> None:
    with time_machine.travel(_START, tick=False):
        ca_cert, ca_key = generate_ca_certificate("Boundary CA", key_size=2048, validity_days=300)
    rng = random.Random(58)
    offsets = [timedelta(0), timedelta(hours=12), timedelta(days=100, minutes=3), timedelta(days=299)]
    offsets += [timedelta(seconds=rng.randrange(0, 299 * 86400)) for _ in range(4)]
    for offset in offsets:
        for kind in ("client", "server"):
            with time_machine.travel(_START + offset, tick=False):
                limit = max_leaf_validity_days(ca_cert, kind=kind)
                expected = min(300 - math.ceil(offset / timedelta(days=1)), _cap(kind))
                assert_that(limit, equal_to(expected))
                _issue(kind, ca_cert, ca_key, limit)
                assert_that(calling(_issue).with_args(kind, ca_cert, ca_key, limit + 1), raises(TinyPkiError))


_START = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)


def _cap(kind: Literal["client", "server"]) -> int:
    return MAX_SERVER_VALIDITY_DAYS if kind == "server" else MAX_CLIENT_VALIDITY_DAYS


def _issue(kind: Literal["client", "server"], ca_cert: bytes, ca_key: bytes, days: int) -> None:
    if kind == "server":
        generate_server_certificate(ca_cert, ca_key, "api.home", ["api.home"], key_size=2048, validity_days=days)
    else:
        generate_client_certificate(ca_cert, ca_key, "alice", key_size=2048, validity_days=days)
