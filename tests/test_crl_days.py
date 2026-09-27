"""The store keeps its CRL lifetime and every republish uses it (issue #122)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography import x509
from hamcrest import assert_that, calling, contains_string, equal_to, raises
from pytest import CaptureFixture

from tiny_pki import TinyPkiError, generate_ca_certificate
from tiny_pki.cli.main import main
from tiny_pki.store import CertificateStore

_CA = generate_ca_certificate("CRL days CA", key_size=2048)


def _cli(store: Path, *words: str) -> None:
    main(["--store", str(store), "--color", "never", *words])


def _crl_lifetime(store: CertificateStore) -> int:
    """Whole days from ``lastUpdate`` to ``nextUpdate`` (``lastUpdate`` is backdated a few minutes)."""
    crl_pem = store.read_crl()
    assert crl_pem is not None
    crl = x509.load_pem_x509_crl(crl_pem)
    assert crl.next_update_utc is not None
    return (crl.next_update_utc - crl.last_update_utc).days


def test_default_lifetime_is_30_days(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "store")
    store.write_ca(*_CA)
    store.publish_crl()
    assert_that(store.crl_validity_days, equal_to(30))
    assert_that(_crl_lifetime(store), equal_to(30))


def test_init_crl_days_is_used_by_every_republish(tmp_path: Path) -> None:
    root = tmp_path / "store"
    store = CertificateStore(root)
    _cli(root, "init", "--key-size", "2048", "--crl-days", "7")
    assert_that(_crl_lifetime(store), equal_to(7))
    for words in (
        ("create", "client", "alice", "--key-size", "2048"),
        ("create", "client", "alice", "--key-size", "2048"),
        ("revoke", "alice"),
        ("delete", "alice"),
        ("crl",),
    ):
        _cli(root, *words)
        assert_that(_crl_lifetime(store), equal_to(7))


def test_crl_days_updates_the_stored_lifetime(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    root = tmp_path / "store"
    store = CertificateStore(root)
    _cli(root, "init", "--key-size", "2048")
    _cli(root, "crl", "--days", "90")
    assert_that(_crl_lifetime(store), equal_to(90))
    _cli(root, "create", "client", "bob", "--key-size", "2048")
    _cli(root, "revoke", "bob")
    assert_that(_crl_lifetime(store), equal_to(90))
    assert_that((store.ca_dir / "crldays").read_text(), equal_to("90\n"))
    capsys.readouterr()
    _cli(root, "list", "ca", "--json")
    assert_that(json.loads(capsys.readouterr().out)["crl_days"], equal_to(90))


@pytest.mark.parametrize(
    "words",
    [("crl", "--days", "0"), ("crl", "--days", "366"), ("crl", "--days", "x"), ("crl", "--days")],
)
def test_crl_days_out_of_range_is_refused_without_writing(
    tmp_path: Path, capsys: CaptureFixture[str], words: tuple[str, ...]
) -> None:
    root = tmp_path / "store"
    store = CertificateStore(root)
    _cli(root, "init", "--key-size", "2048")
    before = store.read_crl()
    capsys.readouterr()
    with pytest.raises(SystemExit):
        _cli(root, *words)
    assert_that(capsys.readouterr().err, contains_string("--days"))
    assert_that(store.read_crl(), equal_to(before))
    assert_that(store.crl_validity_days, equal_to(30))


def test_init_refuses_bad_crl_days_before_creating_the_ca(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    root = tmp_path / "store"
    with pytest.raises(SystemExit):
        _cli(root, "init", "--key-size", "2048", "--crl-days", "400")
    assert_that(capsys.readouterr().err, contains_string("--crl-days between 1 and 365"))
    assert_that(CertificateStore(root).has_ca(), equal_to(False))


def test_library_setter_validates_and_persists(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "store")
    store.write_ca(*_CA)
    assert_that(calling(store.set_crl_validity_days).with_args(0), raises(TinyPkiError, "between 1 and 365"))
    store.publish_crl(validity_days=14)
    assert_that(CertificateStore(store.root).crl_validity_days, equal_to(14))
    assert_that(_crl_lifetime(store), equal_to(14))


def test_corrupt_crldays_is_an_error(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "store")
    store.write_ca(*_CA)
    (store.ca_dir / "crldays").write_text("soon\n")
    assert_that(calling(store.publish_crl), raises(ValueError, "decimal number of days"))


@pytest.mark.parametrize("text", ["0\n", "366\n"])
def test_out_of_range_crldays_file_is_an_error(tmp_path: Path, text: str) -> None:
    store = CertificateStore(tmp_path / "store")
    store.write_ca(*_CA)
    (store.ca_dir / "crldays").write_text(text)
    assert_that(calling(store.publish_crl), raises(TinyPkiError, "between 1 and 365"))
    assert_that(calling(getattr).with_args(store, "crl_validity_days"), raises(TinyPkiError, "between 1 and 365"))


@pytest.mark.parametrize("days", ["1", "365"])
def test_crl_days_bounds_are_accepted(tmp_path: Path, days: str) -> None:
    root = tmp_path / "store"
    store = CertificateStore(root)
    _cli(root, "init", "--key-size", "2048", "--crl-days", days)
    assert_that(_crl_lifetime(store), equal_to(int(days)))
    _cli(root, "crl", "--days", days)
    assert_that(store.crl_validity_days, equal_to(int(days)))


def test_failed_publish_leaves_the_stored_lifetime_unchanged(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    root = tmp_path / "store"
    with pytest.raises(SystemExit):
        _cli(root, "crl", "--days", "7")
    capsys.readouterr()
    _cli(root, "init", "--key-size", "2048")
    store = CertificateStore(root)
    assert_that(store.crl_validity_days, equal_to(30))
    assert_that(_crl_lifetime(store), equal_to(30))


@pytest.mark.parametrize("days", [0, 366, True, 7.5])
def test_publish_crl_refuses_a_bad_explicit_lifetime_without_writing(tmp_path: Path, days: object) -> None:
    store = CertificateStore(tmp_path / "store")
    store.write_ca(*_CA)
    store.publish_crl()
    before = store.read_crl()
    assert_that(calling(store.publish_crl).with_args(validity_days=days), raises(TinyPkiError))
    assert_that(calling(store.set_crl_validity_days).with_args(days), raises(TinyPkiError))
    assert_that(store.read_crl(), equal_to(before))
    assert_that(store.crl_validity_days, equal_to(30))
    assert_that((store.ca_dir / "crldays").exists(), equal_to(False))


@pytest.mark.parametrize("words", [("init", "--crl-days"), ("init", "--crl-days", "--cn", "x")])
def test_init_crl_days_without_a_value_is_refused(
    tmp_path: Path, capsys: CaptureFixture[str], words: tuple[str, ...]
) -> None:
    root = tmp_path / "store"
    with pytest.raises(SystemExit):
        _cli(root, *words)
    assert_that(capsys.readouterr().err, contains_string("Expected a non-empty value for --crl-days"))
    assert_that(CertificateStore(root).has_ca(), equal_to(False))
