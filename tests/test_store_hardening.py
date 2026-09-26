"""Store write paths, modes, and index path validation (issue #99)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import json
import os
import stat
from collections.abc import Iterator
from pathlib import Path

import pytest
from hamcrest import assert_that, calling, equal_to, raises

from tiny_pki import (
    generate_ca_certificate,
    generate_client_certificate,
    get_certificate_expiry,
    get_certificate_fingerprint,
    get_certificate_serial_number,
)
from tiny_pki.store import CertificateStore


@pytest.fixture(scope="module")
def ca_pair() -> tuple[bytes, bytes]:
    return generate_ca_certificate(key_size=2048)


@pytest.fixture
def open_umask() -> Iterator[None]:
    previous = os.umask(0)
    try:
        yield
    finally:
        os.umask(previous)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _store(tmp_path: Path, ca_pair: tuple[bytes, bytes]) -> CertificateStore:
    store = CertificateStore(tmp_path / "store")
    store.write_ca(*ca_pair)
    return store


def _issue(store: CertificateStore, ca_pair: tuple[bytes, bytes], cn: str = "alice") -> tuple[int, bytes, bytes]:
    cert_pem, key_pem = generate_client_certificate(*ca_pair, cn, key_size=2048)
    serial = get_certificate_serial_number(cert_pem)
    store.add_certificate(
        common_name=cn,
        kind="client",
        serial_number=serial,
        cert_pem=cert_pem,
        key_pem=key_pem,
        not_valid_after=get_certificate_expiry(cert_pem),
        fingerprint=get_certificate_fingerprint(cert_pem),
    )
    return serial, cert_pem, key_pem


def test_add_certificate_refuses_in_store_symlink_onto_ca_key(tmp_path: Path, ca_pair: tuple[bytes, bytes]) -> None:
    store = _store(tmp_path, ca_pair)
    cert_pem, key_pem = generate_client_certificate(*ca_pair, "mallory", key_size=2048)
    serial = get_certificate_serial_number(cert_pem)
    (store.clients_dir / f"mallory-{serial:x}.crt").symlink_to(store.ca_key_path)
    assert_that(
        calling(store.add_certificate).with_args(
            common_name="mallory",
            kind="client",
            serial_number=serial,
            cert_pem=cert_pem,
            key_pem=key_pem,
            not_valid_after=get_certificate_expiry(cert_pem),
            fingerprint=get_certificate_fingerprint(cert_pem),
        ),
        raises(ValueError, "symlink"),
    )
    assert_that(store.read_ca()[1], equal_to(ca_pair[1]))


def test_write_bundle_refuses_in_store_symlink_onto_ca_key(tmp_path: Path, ca_pair: tuple[bytes, bytes]) -> None:
    store = _store(tmp_path, ca_pair)
    serial, _, _ = _issue(store, ca_pair)
    (store.bundles_dir / f"alice-{serial:x}.p12").symlink_to(store.ca_key_path)
    assert_that(calling(store.write_bundle).with_args("alice", b"p12"), raises(ValueError, "symlink"))
    assert_that(store.read_ca()[1], equal_to(ca_pair[1]))


def test_write_bundle_refuses_symlinked_bundles_dir(tmp_path: Path, ca_pair: tuple[bytes, bytes]) -> None:
    store = _store(tmp_path, ca_pair)
    _issue(store, ca_pair)
    store.bundles_dir.rmdir()
    store.bundles_dir.symlink_to(store.ca_dir)
    assert_that(calling(store.write_bundle).with_args("alice", b"p12"), raises(ValueError, "symlink"))


@pytest.mark.usefixtures("open_umask")
def test_new_store_dirs_and_index_are_private_under_open_umask(tmp_path: Path, ca_pair: tuple[bytes, bytes]) -> None:
    store = _store(tmp_path, ca_pair)
    _issue(store, ca_pair)
    for directory in (store.root, store.ca_dir, store.clients_dir, store.servers_dir, store.bundles_dir):
        assert_that(_mode(directory), equal_to(0o700))
    assert_that(_mode(store.index_path), equal_to(0o600))
    assert_that(_mode(store.ca_key_path), equal_to(0o600))


def test_existing_world_writable_dirs_lose_world_write_only(tmp_path: Path) -> None:
    root = tmp_path / "store"
    (root / "clients").mkdir(parents=True)
    root.chmod(0o777)
    (root / "clients").chmod(0o777)
    CertificateStore(root).ensure_layout()
    assert_that(_mode(root), equal_to(0o775))
    assert_that(_mode(root / "clients"), equal_to(0o775))


def test_add_certificate_refuses_key_only_symlink_onto_ca_key(tmp_path: Path, ca_pair: tuple[bytes, bytes]) -> None:
    store = _store(tmp_path, ca_pair)
    cert_pem, key_pem = generate_client_certificate(*ca_pair, "mallory", key_size=2048)
    serial = get_certificate_serial_number(cert_pem)
    (store.clients_dir / f"mallory-{serial:x}.key").symlink_to(store.ca_key_path)
    assert_that(
        calling(store.add_certificate).with_args(
            common_name="mallory",
            kind="client",
            serial_number=serial,
            cert_pem=cert_pem,
            key_pem=key_pem,
            not_valid_after=get_certificate_expiry(cert_pem),
            fingerprint=get_certificate_fingerprint(cert_pem),
        ),
        raises(ValueError, "symlink"),
    )
    assert_that(store.read_ca()[1], equal_to(ca_pair[1]))


def test_read_key_refuses_in_store_symlink_onto_ca_key(tmp_path: Path, ca_pair: tuple[bytes, bytes]) -> None:
    store = _store(tmp_path, ca_pair)
    _issue(store, ca_pair)
    entry = store.get_certificate("alice")
    assert entry is not None
    key_file = store.root / entry.key_path
    key_file.unlink()
    key_file.symlink_to(store.ca_key_path)
    assert_that(calling(store.read_key_pem).with_args(entry), raises(ValueError, "symlink"))


def test_read_certificate_refuses_in_store_symlink_onto_ca_key(tmp_path: Path, ca_pair: tuple[bytes, bytes]) -> None:
    store = _store(tmp_path, ca_pair)
    _issue(store, ca_pair)
    entry = store.get_certificate("alice")
    assert entry is not None
    cert_file = store.root / entry.cert_path
    cert_file.unlink()
    cert_file.symlink_to(store.ca_key_path)
    assert_that(calling(store.read_certificate_pem).with_args(entry), raises(ValueError, "symlink"))


def test_ensure_layout_does_not_chmod_through_symlinked_dir(tmp_path: Path, ca_pair: tuple[bytes, bytes]) -> None:
    store = _store(tmp_path, ca_pair)
    outside = tmp_path / "shared"
    outside.mkdir()
    outside.chmod(0o777)
    store.clients_dir.rmdir()
    store.clients_dir.symlink_to(outside)
    store.ensure_layout()
    assert_that(_mode(outside), equal_to(0o777))


def test_legacy_migration_rejects_index_naming_ca_material(tmp_path: Path, ca_pair: tuple[bytes, bytes]) -> None:
    root = tmp_path / "legacy"
    root.mkdir()
    (root / "ca.crt").write_bytes(ca_pair[0])
    (root / "ca.key").write_bytes(ca_pair[1])
    entry = {
        "common_name": "mallory",
        "kind": "client",
        "serial_number": "abc",
        "cert_path": "ca/ca.crt",
        "key_path": "ca/ca.key",
        "not_valid_after": "2099-01-01T00:00:00+00:00",
        "fingerprint": "aa",
        "revoked_at": None,
    }
    (root / "index.json").write_text(json.dumps([entry]), encoding="utf-8")
    store = CertificateStore(root)
    assert_that(calling(store.ensure_layout), raises(ValueError, "Expected index path"))
    assert_that((store.ca_dir / "index.json").exists(), equal_to(False))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("key_path", "ca/ca.key"),
        ("key_path", "clients/ca.key"),
        ("cert_path", "ca/ca.crt"),
        ("key_path", "bundles/alice.key"),
        ("key_path", "clients/nested/alice.key"),
        ("key_path", "clients/alice.crt"),
    ],
)
def test_index_rejects_paths_outside_leaf_dirs(
    tmp_path: Path, ca_pair: tuple[bytes, bytes], field: str, value: str
) -> None:
    store = _store(tmp_path, ca_pair)
    _issue(store, ca_pair)
    entries = json.loads(store.index_path.read_text(encoding="utf-8"))
    entries[0][field] = value
    store.index_path.write_text(json.dumps(entries), encoding="utf-8")
    assert_that(calling(store.list_certificates), raises(ValueError, "Expected index path"))
