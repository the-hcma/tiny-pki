"""CRL numbers stay monotonic and store writes are atomic (issue #102)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography import x509
from hamcrest import assert_that, calling, equal_to, greater_than, raises

from tiny_pki import _fsutil as fsutil_module
from tiny_pki import generate_ca_certificate, generate_crl
from tiny_pki.cli.main import main
from tiny_pki.store import CertificateStore


def _cli(store: Path, *words: str) -> None:
    main(["--store", str(store), "--color", "never", *words])


def _crl_number(store: CertificateStore) -> int:
    crl_pem = store.read_crl()
    assert crl_pem is not None
    crl = x509.load_pem_x509_crl(crl_pem)
    return crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number


def test_cli_crl_number_increases_across_operations(tmp_path: Path) -> None:
    root = tmp_path / "store"
    store = CertificateStore(root)
    _cli(root, "init", "--cn", "Durable CA", "--key-size", "2048")
    numbers = [_crl_number(store)]
    for words in (
        ("create", "client", "alice", "--key-size", "2048"),
        ("revoke", "alice"),
        ("crl",),
        ("delete", "alice"),
    ):
        _cli(root, *words)
        numbers.append(_crl_number(store))
    assert_that(numbers, equal_to(sorted(set(numbers))))
    assert_that(int((store.ca_dir / "crlnumber").read_text()), equal_to(numbers[-1]))


def test_next_crl_number_survives_backward_clock(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "store")
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    store.write_ca(ca_cert, ca_key)
    future = datetime(2100, 1, 1, tzinfo=UTC)
    store.write_crl(generate_crl(ca_cert, ca_key, [], crl_number=store.next_crl_number(now=future)))
    published = _crl_number(store)
    assert_that(store.next_crl_number(), equal_to(published + 1))


def test_next_crl_number_uses_recorded_number_when_crl_was_rolled_back(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "store")
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    store.write_ca(ca_cert, ca_key)
    old_crl = generate_crl(ca_cert, ca_key, [], crl_number=5)
    store.write_crl(generate_crl(ca_cert, ca_key, [], crl_number=2**100))
    store.crl_path.write_bytes(old_crl)
    assert_that(store.next_crl_number(), equal_to(2**100 + 1))


def test_cli_publishes_above_recorded_number(tmp_path: Path) -> None:
    root = tmp_path / "store"
    store = CertificateStore(root)
    _cli(root, "init", "--cn", "Durable CA", "--key-size", "2048")
    (store.ca_dir / "crlnumber").write_text(f"{2**100}\n")
    _cli(root, "crl")
    assert_that(_crl_number(store), equal_to(2**100 + 1))


def test_recorded_crl_number_must_be_decimal(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "store")
    store.ensure_layout()
    (store.ca_dir / "crlnumber").write_text("garbage\n")
    assert_that(calling(store.next_crl_number), raises(ValueError, "decimal CRL number"))


def test_recorded_crl_number_refuses_symlink_without_echoing_target(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "store")
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    store.write_ca(ca_cert, ca_key)
    (store.ca_dir / "crlnumber").symlink_to(store.ca_key_path)
    assert_that(calling(store.next_crl_number), raises(ValueError, "symlink"))


def test_next_crl_number_refuses_to_exceed_20_octets(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "store")
    store.ensure_layout()
    (store.ca_dir / "crlnumber").write_text(f"{2**159 - 1}\n")
    assert_that(calling(store.next_crl_number), raises(ValueError, "below 2\\*\\*159"))


def test_ca_write_failure_keeps_previous_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = CertificateStore(tmp_path / "store")
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    store.write_ca(ca_cert, ca_key)

    def failing_fsync(fd: int) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(fsutil_module.os, "fsync", failing_fsync)
    replacement_cert, replacement_key = generate_ca_certificate(key_size=2048)
    assert_that(
        calling(store.write_ca).with_args(replacement_cert, replacement_key, force=True),
        raises(OSError, "disk full"),
    )
    assert_that(store.read_ca(), equal_to((ca_cert, ca_key)))
    assert_that([p.name for p in store.ca_dir.iterdir() if p.name.endswith(".tmp")], equal_to([]))


def test_plain_files_get_explicit_mode(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "store")
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    store.write_ca(ca_cert, ca_key)
    store.ca_cert_path.chmod(0o666)
    store.write_ca(ca_cert, ca_key, force=True)
    assert_that(stat.S_IMODE(store.ca_cert_path.stat().st_mode), equal_to(0o644))
    assert_that(store.ca_cert_path.stat().st_size, greater_than(0))
