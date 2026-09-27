"""Public store operations keep crl.pem in step with index.json (issue #118)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import contextlib
import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from hamcrest import assert_that, contains_string, equal_to, has_item, is_, is_not, none
from pytest import CaptureFixture

from tiny_pki import generate_ca_certificate
from tiny_pki.check import Status
from tiny_pki.cli.main import main
from tiny_pki.store import CertificateStore, check_store

_CA = generate_ca_certificate("API CA", key_size=2048)


def _store(tmp_path: Path) -> CertificateStore:
    store = CertificateStore(tmp_path / "store")
    store.write_ca(*_CA)
    store.publish_crl()
    return store


def _crl_serials(store: CertificateStore) -> set[int]:
    crl_pem = store.read_crl()
    assert crl_pem is not None
    return {entry.serial_number for entry in x509.load_pem_x509_crl(crl_pem)}


def test_mark_revoked_republishes_the_crl(tmp_path: Path) -> None:
    store = _store(tmp_path)
    entry = store.issue_client("alice", key_size=2048)
    store.mark_revoked("alice")
    assert_that(_crl_serials(store), equal_to({int(entry.serial_number, 16)}))


def test_reissue_republishes_the_superseded_serial(tmp_path: Path) -> None:
    store = _store(tmp_path)
    first = store.issue_client("alice", key_size=2048)
    second = store.issue_client("alice", key_size=2048)
    assert_that(_crl_serials(store), equal_to({int(first.serial_number, 16)}))
    live = store.get_certificate("alice")
    assert live is not None
    assert_that(live.serial_number, equal_to(second.serial_number))


def test_issue_server_revoke_and_delete_keep_the_crl_current(tmp_path: Path) -> None:
    store = _store(tmp_path)
    server = store.issue_server("api.home", ["api.home"], key_size=2048)
    client = store.issue_client("bob", key_size=2048)
    store.revoke("api.home")
    assert_that(_crl_serials(store), equal_to({int(server.serial_number, 16)}))
    store.delete("bob", force=True)
    assert_that(_crl_serials(store), equal_to({int(server.serial_number, 16), int(client.serial_number, 16)}))
    assert_that(store.get_certificate("bob"), is_(none()))


def test_add_certificate_without_a_ca_writes_no_crl(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "store")
    store.add_certificate(
        common_name="alice",
        kind="client",
        serial_number=0xA1,
        cert_pem=b"cert",
        key_pem=b"key",
        not_valid_after=datetime.now(UTC) + timedelta(days=30),
        fingerprint="fp",
    )
    store.mark_revoked("alice")
    assert_that(store.read_crl(), is_(none()))


def test_store_operations_do_not_import_the_cli(tmp_path: Path) -> None:
    script = (
        "import sys\n"
        "from tiny_pki import generate_ca_certificate\n"
        "from tiny_pki.store import CertificateStore, check_store\n"
        "store = CertificateStore(sys.argv[1])\n"
        "store.write_ca(*generate_ca_certificate(key_size=2048))\n"
        "store.issue_client('alice', key_size=2048)\n"
        "store.revoke('alice')\n"
        "check_store(store, include_revoked=True)\n"
        "assert not any(m.startswith('tiny_pki.cli') for m in sys.modules), sorted(sys.modules)\n"
    )
    subprocess.run([sys.executable, "-c", script, str(tmp_path / "store")], check=True)


def test_check_store_matches_cli_check_json(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    store = _store(tmp_path)
    store.issue_client("alice", key_size=2048)
    store.issue_server("api.home", ["api.home"], key_size=2048)
    store.issue_client("bob", key_size=2048)
    store.revoke("bob")
    rows = check_store(store, include_revoked=True)
    with contextlib.suppress(SystemExit):
        main(["--store", str(store.root), "--color", "never", "check", "--include-revoked", "--json"])
    cli_rows = {row["name"]: (row["status"], row["reasons"]) for row in json.loads(capsys.readouterr().out)["results"]}
    assert_that(
        {name: (result.status.value, list(result.reasons)) for name, result in rows},
        equal_to(cli_rows),
    )
    assert_that([result.status for name, result in rows if name == "bob"], equal_to([Status.REVOKED]))


def test_check_store_flags_a_crl_missing_an_index_revocation(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.issue_client("alice", key_size=2048)
    stale = store.read_crl()
    assert stale is not None
    store.revoke("alice")
    store.crl_path.write_bytes(stale)
    crl_rows = [result for name, result in check_store(store, kinds={"client"}) if name == "crl"]
    assert_that([r.status for r in crl_rows], equal_to([Status.UNTRUSTED]))
    assert_that(crl_rows[0].reasons, has_item(contains_string("revoked in index.json")))


def test_cli_revoke_without_a_ca_does_not_claim_a_crl_update(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    store = CertificateStore(tmp_path / "store")
    store.add_certificate(
        common_name="alice",
        kind="client",
        serial_number=0xA1,
        cert_pem=b"cert",
        key_pem=b"key",
        not_valid_after=datetime.now(UTC) + timedelta(days=30),
        fingerprint="fp",
    )
    main(["--store", str(store.root), "--color", "never", "revoke", "alice"])
    captured = capsys.readouterr()
    assert_that(captured.out, is_not(contains_string("crl updated")))
    assert_that(captured.err, contains_string("no CRL was published"))
    assert_that(store.read_crl(), is_(none()))
