"""Routine client rotation keeps the previous certificate live (issue #123)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import contextlib
import json
from pathlib import Path

import pytest
from cryptography import x509
from hamcrest import assert_that, calling, contains_string, equal_to, has_item, is_not, raises
from pytest import CaptureFixture

from tiny_pki import generate_ca_certificate
from tiny_pki.cli.main import main
from tiny_pki.store import CertificateStore, check_store

_CA = generate_ca_certificate("Rotation CA", key_size=2048)


def _run(store: Path, *words: str, capsys: CaptureFixture[str], expect_ok: bool = True) -> tuple[str, str]:
    argv = ["--store", str(store), "--color", "never", *words]
    if expect_ok:
        main(argv)
    else:
        with pytest.raises(SystemExit):
            main(argv)
    captured = capsys.readouterr()
    return captured.out, captured.err


def _crl_serials(store: CertificateStore) -> set[int]:
    crl_pem = store.read_crl()
    assert crl_pem is not None
    return {entry.serial_number for entry in x509.load_pem_x509_crl(crl_pem)}


@pytest.fixture
def rotated(tmp_path: Path) -> tuple[CertificateStore, str, str]:
    store = CertificateStore(tmp_path / "store")
    store.write_ca(*_CA)
    store.publish_crl()
    old = store.issue_client("alice", key_size=2048)
    new = store.issue_client("alice", key_size=2048, keep_previous=True)
    return store, old.serial_number, new.serial_number


def test_keep_previous_leaves_both_live_and_the_crl_empty(rotated: tuple[CertificateStore, str, str]) -> None:
    store, old, new = rotated
    live = [e.serial_number for e in store.list_certificates(status="active")]
    assert_that(sorted(live), equal_to(sorted([old, new])))
    assert_that(_crl_serials(store), equal_to(set()))
    for serial in (old, new):
        entry = store.get_certificate(f"0x{serial}")
        assert entry is not None
        assert_that(store.read_certificate_pem(entry).startswith(b"-----BEGIN CERTIFICATE"), equal_to(True))


def test_cn_resolves_to_the_newest_live_certificate(rotated: tuple[CertificateStore, str, str]) -> None:
    store, _, new = rotated
    entry = store.get_certificate("alice")
    assert entry is not None
    assert_that(entry.serial_number, equal_to(new))
    assert_that(store.superseded_serials(), equal_to({rotated[1]: new}))


def test_revoke_and_delete_by_cn_refuse_while_two_are_live(rotated: tuple[CertificateStore, str, str]) -> None:
    store, old, new = rotated
    assert_that(calling(store.revoke).with_args("alice"), raises(ValueError, "2 live certificates share"))
    assert_that(calling(store.delete).with_args("alice", force=True), raises(ValueError, f"0x{old}"))
    store.revoke(f"0x{old}")
    assert_that(_crl_serials(store), equal_to({int(old, 16)}))
    assert_that(store.superseded_serials(), equal_to({}))
    remaining = store.get_certificate("alice")
    assert remaining is not None
    assert_that(remaining.serial_number, equal_to(new))
    store.revoke("alice")
    assert_that(_crl_serials(store), equal_to({int(old, 16), int(new, 16)}))


def test_default_reissue_still_revokes_the_previous_serial(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "store")
    store.write_ca(*_CA)
    old = store.issue_client("bob", key_size=2048)
    store.issue_client("bob", key_size=2048)
    assert_that(_crl_serials(store), equal_to({int(old.serial_number, 16)}))


def test_plain_reissue_after_rotation_revokes_every_older_serial(
    rotated: tuple[CertificateStore, str, str], tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    store, old, new = rotated
    out, _ = _run(store.root, "create", "client", "alice", "--key-size", "2048", capsys=capsys)
    assert_that(out, is_not(contains_string("stays live")))
    assert_that(_crl_serials(store), equal_to({int(old, 16), int(new, 16)}))
    assert_that(store.superseded_serials(), equal_to({}))


def test_keep_previous_only_pairs_certificates_of_the_same_kind(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "store")
    store.write_ca(*_CA)
    server = store.issue_server("api.home", ["api.home"], key_size=2048)
    client = store.issue_client("api.home", key_size=2048, keep_previous=True)
    assert_that(store.superseded_serials(), equal_to({}))
    assert_that(_crl_serials(store), equal_to({int(server.serial_number, 16)}))
    live = store.get_certificate("api.home", require_unique=True)
    assert live is not None
    assert_that(live.serial_number, equal_to(client.serial_number))


def test_check_store_marks_the_older_one_superseded(rotated: tuple[CertificateStore, str, str]) -> None:
    store, old, new = rotated
    rows = dict(check_store(store, kinds={"client"}))
    superseded_name = f"alice (superseded, 0x{old})"
    assert_that(sorted(rows), equal_to(["alice", superseded_name]))
    assert_that(rows[superseded_name].reasons, has_item(contains_string(f"superseded by serial {new}")))


def test_cli_rotation_flow(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    root = tmp_path / "store"
    store = CertificateStore(root)
    _run(root, "init", "--key-size", "2048", capsys=capsys)
    _run(root, "create", "client", "alice", "--key-size", "2048", capsys=capsys)
    out, _ = _run(root, "create", "client", "alice", "--key-size", "2048", "--keep-previous", capsys=capsys)
    old, new = store.superseded_serials().popitem()
    assert_that(out, contains_string(f"previous serial {old} stays live"))

    out, _ = _run(root, "list", "clients", capsys=capsys)
    assert_that(out, contains_string(f"superseded by {new}"))
    out, _ = _run(root, "list", "clients", "--json", capsys=capsys)
    by_serial = {row["serial"]: row["superseded_by"] for row in json.loads(out)}
    assert_that(by_serial, equal_to({old: new, new: None}))

    with contextlib.suppress(SystemExit):
        main(["--store", str(root), "--color", "never", "check", "--kind", "client"])
    assert_that(capsys.readouterr().out, contains_string(f"alice (superseded, 0x{old})"))

    _, err = _run(root, "revoke", "alice", capsys=capsys, expect_ok=False)
    assert_that(err, contains_string("live certificates share"))
    _, err = _run(root, "revoke", "alice", "--dry-run", capsys=capsys, expect_ok=False)
    assert_that(err, contains_string("live certificates share"))
    delete_attempts = [("--dry-run",), ("--force",), ("--force", "--dry-run")]
    for flags in delete_attempts:
        words = ("delete", "alice", *flags)
        _, err = _run(root, *words, capsys=capsys, expect_ok=False)
        assert_that(err, contains_string(f"0x{old}"))
        assert_that(err, contains_string(f"0x{new}"))
    assert_that(sorted(e.serial_number for e in store.list_certificates(status="active")), equal_to(sorted([old, new])))
    _run(root, "revoke", f"0x{old}", capsys=capsys)
    assert_that(_crl_serials(store), equal_to({int(old, 16)}))


def test_keep_previous_is_client_only(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    root = tmp_path / "store"
    _run(root, "init", "--key-size", "2048", capsys=capsys)
    _, err = _run(
        root, "create", "server", "api.home", "--key-size", "2048", "--keep-previous", capsys=capsys, expect_ok=False
    )
    assert_that(err, contains_string("only supported for client"))
