"""The store keeps a key-free public/ directory for TLS servers (issue #119)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest
from hamcrest import assert_that, calling, equal_to, raises

from tiny_pki import generate_ca_certificate
from tiny_pki.cli.main import main
from tiny_pki.store import CertificateStore

_CA = generate_ca_certificate("Public CA", key_size=2048)


def _cli(store: Path, *words: str) -> None:
    main(["--store", str(store), "--color", "never", *words])


def _mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def test_public_dir_mirrors_ca_cert_and_crl_with_open_modes(tmp_path: Path) -> None:
    root = tmp_path / "store"
    store = CertificateStore(root)
    old_umask = os.umask(0o077)
    try:
        _cli(root, "init", "--key-size", "2048")
    finally:
        os.umask(old_umask)
    public = store.public_dir
    assert_that(sorted(p.name for p in public.iterdir()), equal_to(["ca.crt", "crl.pem"]))
    assert_that(_mode(public), equal_to(0o755))
    assert_that(_mode(public / "ca.crt"), equal_to(0o644))
    assert_that(_mode(public / "crl.pem"), equal_to(0o644))
    assert_that((public / "ca.crt").read_bytes(), equal_to(store.ca_cert_path.read_bytes()))
    assert_that((public / "crl.pem").read_bytes(), equal_to(store.crl_path.read_bytes()))
    assert_that(_mode(store.ca_dir), equal_to(0o700))


def test_public_crl_follows_every_republish_by_rename(tmp_path: Path) -> None:
    root = tmp_path / "store"
    store = CertificateStore(root)
    _cli(root, "init", "--key-size", "2048")
    _cli(root, "create", "client", "alice", "--key-size", "2048")
    public_crl = store.public_dir / "crl.pem"
    inode = public_crl.stat().st_ino
    _cli(root, "revoke", "alice")
    assert_that(public_crl.read_bytes(), equal_to(store.crl_path.read_bytes()))
    assert_that(public_crl.stat().st_ino != inode, equal_to(True))


def test_existing_store_gains_public_dir_on_next_write(tmp_path: Path) -> None:
    root = tmp_path / "store"
    store = CertificateStore(root)
    store.write_ca(*_CA)
    store.publish_crl()
    shutil.rmtree(store.public_dir)
    _cli(root, "crl")
    assert_that((store.public_dir / "ca.crt").read_bytes(), equal_to(store.ca_cert_path.read_bytes()))
    assert_that((store.public_dir / "crl.pem").read_bytes(), equal_to(store.crl_path.read_bytes()))


def test_public_dir_symlink_is_refused(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "store")
    store.write_ca(*_CA)
    shutil.rmtree(store.public_dir)
    store.public_dir.symlink_to(store.ca_dir)
    assert_that(calling(store.publish_crl), raises(ValueError, "symlink"))


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses permission checks")
def test_other_user_view_reaches_public_but_not_ca(tmp_path: Path) -> None:
    root = tmp_path / "store"
    store = CertificateStore(root)
    _cli(root, "init", "--key-size", "2048")
    for path in (store.public_dir / "ca.crt", store.public_dir / "crl.pem"):
        assert_that(_mode(path) & 0o004, equal_to(0o004))
    assert_that(_mode(store.public_dir) & 0o005, equal_to(0o005))
    assert_that(_mode(store.ca_dir) & 0o077, equal_to(0))
    assert_that(any(p.name.endswith(".key") for p in store.public_dir.iterdir()), equal_to(False))


def test_existing_public_dir_modes_are_normalized(tmp_path: Path) -> None:
    root = tmp_path / "store"
    store = CertificateStore(root)
    _cli(root, "init", "--key-size", "2048")
    (store.public_dir / "crl.pem").chmod(0o600)
    (store.public_dir / "ca.crt").chmod(0o666)
    store.public_dir.chmod(0o777)
    _cli(root, "crl")
    assert_that(_mode(store.public_dir), equal_to(0o755))
    assert_that(_mode(store.public_dir / "crl.pem"), equal_to(0o644))
    assert_that(_mode(store.public_dir / "ca.crt"), equal_to(0o644))
    store.public_dir.chmod(0o700)
    store.publish_crl()
    assert_that(_mode(store.public_dir), equal_to(0o755))


def test_non_directory_public_is_refused(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "store")
    store.write_ca(*_CA)
    shutil.rmtree(store.public_dir)
    store.public_dir.write_text("not a directory")
    assert_that(calling(store.publish_crl), raises(ValueError, "to be a directory"))


def test_legacy_migration_on_read_fills_public_dir(tmp_path: Path) -> None:
    root = tmp_path / "legacy"
    root.mkdir()
    (root / "ca.crt").write_bytes(_CA[0])
    (root / "ca.key").write_bytes(_CA[1])
    (root / "index.json").write_text("[]\n", encoding="utf-8")
    store = CertificateStore(root)
    assert_that(store.list_certificates(), equal_to([]))
    assert_that((store.public_dir / "ca.crt").read_bytes(), equal_to(_CA[0]))
    assert_that(_mode(store.public_dir / "ca.crt"), equal_to(0o644))
