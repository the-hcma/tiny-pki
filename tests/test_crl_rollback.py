"""An old or stale CRL must not make a revoked certificate look good (issue #98)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import time_machine
from hamcrest import assert_that, contains_string, equal_to, has_item
from pytest import CaptureFixture

from tiny_pki import Status, check_certificate, generate_ca_certificate, generate_client_certificate, generate_crl
from tiny_pki.cli.main import main
from tiny_pki.store import CertificateStore


def _cli(store: Path, *words: str) -> None:
    main(["--store", str(store), "--color", "never", *words])


def _check_json(store: Path, capsys: CaptureFixture[str], *words: str) -> tuple[int, dict[str, Any]]:
    capsys.readouterr()
    try:
        _cli(store, "check", "--json", *words)
        code = 0
    except SystemExit as exited:
        code = int(exited.code or 0)
    return code, json.loads(capsys.readouterr().out)


def _row(payload: dict[str, Any], name: str) -> dict[str, Any]:
    return next(r for r in payload["results"] if r["name"] == name)


def test_check_certificate_with_expired_crl_is_untrusted() -> None:
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    leaf, _ = generate_client_certificate(ca_cert, ca_key, "alice", key_size=2048)
    crl = generate_crl(ca_cert, ca_key, [], validity_days=1)
    later = datetime.now(UTC) + timedelta(days=2)
    result = check_certificate(leaf, now=later, ca_cert_pem=ca_cert, crl_pem=crl)
    assert_that(result.status, equal_to(Status.UNTRUSTED))
    assert_that(result.reasons, has_item(contains_string("revocation status unknown")))


def test_check_certificate_with_fresh_crl_is_ok() -> None:
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    leaf, _ = generate_client_certificate(ca_cert, ca_key, "alice", key_size=2048)
    crl = generate_crl(ca_cert, ca_key, [])
    assert_that(check_certificate(leaf, ca_cert_pem=ca_cert, crl_pem=crl).status, equal_to(Status.OK))


def _store_with_revoked_bob(tmp_path: Path) -> tuple[Path, bytes]:
    root = tmp_path / "store"
    _cli(root, "init", "--cn", "Rollback CA", "--key-size", "2048")
    _cli(root, "create", "client", "alice", "--key-size", "2048")
    _cli(root, "create", "client", "bob", "--key-size", "2048")
    old_crl = CertificateStore(root).crl_path.read_bytes()
    _cli(root, "revoke", "bob")
    return root, old_crl


def test_store_check_fails_when_crl_rolled_back(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    root, old_crl = _store_with_revoked_bob(tmp_path)
    CertificateStore(root).crl_path.write_bytes(old_crl)
    code, payload = _check_json(root, capsys, "--include-revoked")
    assert_that(code, equal_to(2))
    crl_row = _row(payload, "crl")
    assert_that(crl_row["status"], equal_to("untrusted"))
    assert_that(crl_row["reasons"], has_item(contains_string("missing 1 serial(s) revoked in index.json")))
    bob = _row(payload, "bob")
    assert_that(bob["status"], equal_to("revoked"))
    assert_that(bob["reasons"], has_item(contains_string("revoked in index.json")))


def test_store_check_without_crl_but_revocations_is_unknown(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    root, _ = _store_with_revoked_bob(tmp_path)
    CertificateStore(root).crl_path.unlink()
    capsys.readouterr()
    try:
        _cli(root, "check")
        code = 0
    except SystemExit as exited:
        code = int(exited.code or 0)
    assert_that(code, equal_to(3))
    assert_that(capsys.readouterr().err, contains_string("serial(s) revoked in index.json"))


def test_store_check_flags_rolled_back_crl_even_when_kind_excludes_crl(
    tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    root, old_crl = _store_with_revoked_bob(tmp_path)
    CertificateStore(root).crl_path.write_bytes(old_crl)
    code, payload = _check_json(root, capsys, "--kind", "client")
    assert_that(code, equal_to(2))
    assert_that(_row(payload, "crl")["status"], equal_to("untrusted"))


def test_store_check_without_crl_or_revocations_is_ok(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    root = tmp_path / "store"
    _cli(root, "init", "--cn", "No CRL CA", "--key-size", "2048")
    _cli(root, "create", "client", "alice", "--key-size", "2048")
    CertificateStore(root).crl_path.unlink()
    code, payload = _check_json(root, capsys)
    assert_that(code, equal_to(0))
    assert_that(_row(payload, "alice")["status"], equal_to("ok"))


def test_inspect_reports_index_revocation_despite_rolled_back_crl(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    root, old_crl = _store_with_revoked_bob(tmp_path)
    CertificateStore(root).crl_path.write_bytes(old_crl)
    capsys.readouterr()
    _cli(root, "inspect", "bob")
    out = capsys.readouterr().out
    assert_that(out, contains_string("revoked in index.json"))
    assert_that(out, contains_string("(revoked"))


def test_store_check_with_expired_crl_is_critical(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    root, _ = _store_with_revoked_bob(tmp_path)
    with time_machine.travel(datetime.now(UTC) + timedelta(days=45), tick=False):
        code, payload = _check_json(root, capsys)
    assert_that(code, equal_to(2))
    alice = _row(payload, "alice")
    assert_that(alice["status"], equal_to("untrusted"))
    assert_that(alice["reasons"], has_item(contains_string("CRL expired")))


def test_expired_crl_keeps_index_revocation_reason(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    root, _ = _store_with_revoked_bob(tmp_path)
    with time_machine.travel(datetime.now(UTC) + timedelta(days=45), tick=False):
        code, payload = _check_json(root, capsys, "--include-revoked")
    assert_that(code, equal_to(2))
    bob = _row(payload, "bob")
    assert_that(bob["status"], equal_to("untrusted"))
    assert_that(bob["reasons"], has_item(contains_string("revoked in index.json")))
