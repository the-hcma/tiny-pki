"""`tiny-pki check`: store scan, alert windows, output modes, exit codes (issue #48)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import time_machine
from hamcrest import (
    assert_that,
    contains_string,
    equal_to,
    has_entries,
    has_length,
    is_not,
)
from pytest import CaptureFixture

from tiny_pki import generate_ca_certificate, generate_crl
from tiny_pki.cli.main import main


def test_default_window_on_a_fresh_store_is_ok(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    store = _store(tmp_path, capsys)
    assert_that(_check(store), equal_to(0))
    out = capsys.readouterr().out
    for name in ("ca", "crl", "alice", "api.home"):
        assert_that(out, contains_string(name))
    assert_that(out, contains_string("check: 4 ok; default window"))


def test_within_flags_expiring_as_warning(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    store = _store(tmp_path, capsys)
    assert_that(_check(store, "--within", "100"), equal_to(1))
    out = capsys.readouterr().out
    assert_that(out, contains_string("expiring"))
    assert_that(out, contains_string("check: 2 expiring, 2 ok; within 100 days"))


def test_expired_is_critical_and_sorted_first(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    store = _store(tmp_path, capsys)
    with time_machine.travel(datetime.now(UTC) + timedelta(days=100), tick=False):
        assert_that(_check(store), equal_to(2))
    out = capsys.readouterr().out
    lines = out.splitlines()
    assert_that(lines[1], contains_string("crl"))
    assert_that(lines[-1], contains_string("2 untrusted, 1 expired, 1 ok"))


def test_by_date_and_kind_filter(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    store = _store(tmp_path, capsys)
    assert_that(_check(store, "--by", "2100-01-01", "--kind", "server", "--kind", "ca"), equal_to(1))
    out = capsys.readouterr().out
    assert_that(out, contains_string("api.home"))
    assert_that(out, is_not(contains_string("alice")))
    assert_that(out, contains_string("check: 2 expiring; by 2100-01-01"))
    assert_that(_check(store, "--within", "10", "--by", "2100-01-01", "--kind", "client"), equal_to(0))
    assert_that(capsys.readouterr().out, contains_string("whichever is earlier"))


def test_quiet_prints_only_problems(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    store = _store(tmp_path, capsys)
    assert_that(_check(store, "--quiet"), equal_to(0))
    assert_that(capsys.readouterr().out, equal_to(""))
    assert_that(_check(store, "--quiet", "--within", "100"), equal_to(1))
    out = capsys.readouterr().out
    assert_that(out, contains_string("api.home"))
    assert_that(out, is_not(contains_string("alice")))


def test_json_output(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    store = _store(tmp_path, capsys)
    assert_that(_check(store, "--json", "--within", "100"), equal_to(1))
    payload = json.loads(capsys.readouterr().out)
    assert_that(payload["status"], equal_to("expiring"))
    assert_that(payload["results"], has_length(4))
    server = next(r for r in payload["results"] if r["name"] == "api.home")
    assert_that(
        server,
        has_entries(
            kind="server",
            status="expiring",
            subject="api.home",
            issuer="Check CLI CA",
            days_remaining=89,
        ),
    )
    assert_that(sorted(server), equal_to(sorted(_JSON_FIELDS)))
    crl = next(r for r in payload["results"] if r["name"] == "crl")
    assert_that(crl["kind"], equal_to("crl"))


def test_revoked_only_with_include_revoked(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    store = _store(tmp_path, capsys)
    main(["--store", str(store), "--color", "never", "revoke", "alice"])
    capsys.readouterr()
    assert_that(_check(store), equal_to(0))
    assert_that(capsys.readouterr().out, is_not(contains_string("alice")))
    assert_that(_check(store, "--include-revoked"), equal_to(2))
    out = capsys.readouterr().out
    assert_that(out, contains_string("revoked"))
    assert_that(out, contains_string("alice"))


def test_crl_from_another_ca_is_untrusted(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    store = _store(tmp_path, capsys)
    other_cert, other_key = generate_ca_certificate("Other CA", key_size=2048)
    (store / "ca" / "crl.pem").write_bytes(generate_crl(other_cert, other_key, []))
    assert_that(_check(store, "--kind", "crl", "--kind", "client"), equal_to(2))
    out = capsys.readouterr().out
    assert_that(out, contains_string("untrusted"))
    assert_that(out, contains_string("1 untrusted, 1 ok"))


def test_store_with_offline_ca_key(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    store = _store(tmp_path, capsys)
    (store / "ca" / "ca.key").unlink()
    assert_that(_check(store), equal_to(0))
    assert_that(capsys.readouterr().out, contains_string("check: 4 ok"))
    (store / "ca" / "ca.crt").unlink()
    assert_that(_check(store), equal_to(3))
    assert_that(capsys.readouterr().err, contains_string("Expected a CA certificate at"))


@pytest.mark.parametrize(
    ("words", "message"),
    [
        (("--within", "soon"), "Expected --within as a whole number of days"),
        (("--within", "-1"), "between 0 and 36500 days"),
        (("--within", "999999999999"), "between 0 and 36500 days"),
        (("--by", "31/12/2026"), "Expected --by YYYY-MM-DD"),
        (("--kind", "leaf"), "Expected --kind in ca, client, crl, server, got leaf"),
        (("--within",), "Expected a non-empty value for --within"),
        (("--ca", "ca.crt"), "--ca / --crl / --password-file apply to file targets"),
        (("--crl", "crl.pem"), "--ca / --crl / --password-file apply to file targets"),
    ],
)
def test_usage_errors_exit_unknown(
    tmp_path: Path, capsys: CaptureFixture[str], words: tuple[str, ...], message: str
) -> None:
    store = _store(tmp_path, capsys)
    assert_that(_check(store, *words), equal_to(3))
    assert_that(capsys.readouterr().err, contains_string(message))


def test_missing_store_exits_unknown(capsys: CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TINY_PKI_STORE", raising=False)
    with pytest.raises(SystemExit) as exited:
        main(["--color", "never", "check"])
    assert_that(exited.value.code, equal_to(3))
    assert_that(capsys.readouterr().err, contains_string("--store"))


_JSON_FIELDS = (
    "cutoff",
    "days_remaining",
    "issuer",
    "kind",
    "name",
    "not_after",
    "not_before",
    "reasons",
    "serial_number",
    "status",
    "subject",
)


def _check(store: Path, *words: str) -> int:
    try:
        main(["--store", str(store), "--color", "never", "check", *words])
    except SystemExit as exited:
        return int(exited.code or 0)
    return 0


def _store(tmp_path: Path, capsys: CaptureFixture[str]) -> Path:
    store = tmp_path / "ca"
    base = ["--store", str(store), "--color", "never"]
    main([*base, "init", "--cn", "Check CLI CA", "--key-size", "2048"])
    main([*base, "create", "client", "alice", "--key-size", "2048"])
    main([*base, "create", "server", "api.home", "--key-size", "2048"])
    capsys.readouterr()
    return store
