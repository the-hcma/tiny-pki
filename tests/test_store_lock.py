"""Store writers serialize on an exclusive flock on ca/.lock (issue #117)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import subprocess
import sys
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from hamcrest import assert_that, calling, contains_inanyorder, equal_to, has_length, is_, raises

from tiny_pki import TinyPkiError, generate_ca_certificate, generate_crl
from tiny_pki.store import CertificateStore

_CA = generate_ca_certificate("Lock CA", key_size=2048)

_TRY_LOCK = """
import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_RDWR)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    sys.exit(1)
sys.exit(0)
"""


def _store(tmp_path: Path) -> CertificateStore:
    store = CertificateStore(tmp_path / "store")
    store.write_ca(*_CA)
    store.publish_crl()
    return store


def _add(store: CertificateStore, name: str, serial: int) -> None:
    store.add_certificate(
        common_name=name,
        kind="client",
        serial_number=serial,
        cert_pem=b"cert",
        key_pem=b"key",
        not_valid_after=datetime.now(UTC) + timedelta(days=30),
        fingerprint=f"fp-{serial}",
    )


def _crl_serials(store: CertificateStore) -> set[int]:
    crl_pem = store.read_crl()
    assert crl_pem is not None
    return {entry.serial_number for entry in x509.load_pem_x509_crl(crl_pem)}


def _other_process_can_lock(store: CertificateStore) -> bool:
    result = subprocess.run([sys.executable, "-c", _TRY_LOCK, str(store.lock_path)], check=False)
    return result.returncode == 0


def test_lock_excludes_other_processes_and_is_released(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with store.lock():
        assert_that(_other_process_can_lock(store), is_(False))
    assert_that(_other_process_can_lock(store), is_(True))
    assert_that(store.lock_path.stat().st_mode & 0o777, equal_to(0o600))


def test_lock_is_reentrant_within_a_thread(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with store.lock(), store.lock():
        _add(store, "alice", 0xA1)
        store.mark_revoked("alice")
    assert_that(_other_process_can_lock(store), is_(True))


def test_lock_is_released_when_the_body_raises(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(RuntimeError), store.lock():
        raise RuntimeError("boom")
    assert_that(_other_process_can_lock(store), is_(True))
    with pytest.raises(RuntimeError), store.lock(), store.lock():
        raise RuntimeError("nested boom")
    assert_that(_other_process_can_lock(store), is_(True))
    with store.lock():
        assert_that(_other_process_can_lock(store), is_(False))


def test_mutation_waits_for_the_lock(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _add(store, "alice", 0xA1)
    done = threading.Event()

    def revoke() -> None:
        CertificateStore(store.root).mark_revoked("alice")
        done.set()

    with store.lock():
        worker = threading.Thread(target=revoke)
        worker.start()
        assert_that(done.wait(0.5), is_(False))
    worker.join(10)
    assert_that(done.is_set(), is_(True))


def test_publish_under_lock_never_drops_a_concurrent_revocation(tmp_path: Path) -> None:
    store = _store(tmp_path)
    names = [f"user{i}" for i in range(8)]
    for i, name in enumerate(names, start=1):
        _add(store, name, 0x100 + i)
    stop = threading.Event()
    errors: list[BaseException] = []

    def timer() -> None:
        timer_store = CertificateStore(store.root)
        try:
            while not stop.is_set():
                timer_store.publish_crl()
        except BaseException as exc:  # noqa: BLE001 - surfaced by the assertion below
            errors.append(exc)

    worker = threading.Thread(target=timer)
    worker.start()
    try:
        for name in names:
            store.mark_revoked(name)
            store.publish_crl()
    finally:
        stop.set()
        worker.join(30)
    assert_that(errors, equal_to([]))
    assert_that(_crl_serials(store), equal_to({0x100 + i for i in range(1, len(names) + 1)}))


def test_concurrent_writers_never_lose_an_index_update(tmp_path: Path) -> None:
    store = _store(tmp_path)
    errors: list[BaseException] = []

    def issue(offset: int) -> None:
        writer = CertificateStore(store.root)
        try:
            for i in range(10):
                _add(writer, f"t{offset}-{i}", 0x1000 * (offset + 1) + i)
        except BaseException as exc:  # noqa: BLE001 - surfaced by the assertion below
            errors.append(exc)

    workers = [threading.Thread(target=issue, args=(n,)) for n in range(4)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(30)
    assert_that(errors, equal_to([]))
    names = [entry.common_name for entry in store.list_certificates()]
    assert_that(names, has_length(40))
    assert_that(names, contains_inanyorder(*[f"t{n}-{i}" for n in range(4) for i in range(10)]))


_MUTATIONS: dict[str, Callable[[CertificateStore], object]] = {
    "add_certificate": lambda store: _add(store, "bob", 0xB0B),
    "delete_certificate": lambda store: store.delete_certificate("alice", force=True),
    "ensure_layout": lambda store: store.ensure_layout(),
    "mark_revoked": lambda store: store.mark_revoked("alice"),
    "write_bundle": lambda store: store.write_bundle("alice", b"p12"),
    "write_ca": lambda store: store.write_ca(*_CA, force=True),
    "write_crl": lambda store: store.write_crl(generate_crl(*_CA, [], crl_number=store.next_crl_number())),
}


@pytest.mark.parametrize("name", sorted(_MUTATIONS))
def test_every_mutation_refuses_without_flock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    store = _store(tmp_path)
    _add(store, "alice", 0xA1)
    before = {p: p.read_bytes() for p in sorted(store.root.rglob("*")) if p.is_file()}
    monkeypatch.setattr(sys, "platform", "win32")
    assert_that(calling(_MUTATIONS[name]).with_args(store), raises(TinyPkiError, "without a lock"))
    assert_that({p: p.read_bytes() for p in sorted(store.root.rglob("*")) if p.is_file()}, equal_to(before))
    assert_that([e.common_name for e in store.list_certificates()], equal_to(["alice"]))


def _legacy_store(tmp_path: Path) -> CertificateStore:
    root = tmp_path / "legacy"
    root.mkdir()
    (root / "ca.crt").write_bytes(_CA[0])
    (root / "ca.key").write_bytes(_CA[1])
    (root / "index.json").write_text("[]\n", encoding="utf-8")
    return CertificateStore(root)


def test_first_read_of_a_legacy_store_migrates_under_the_lock(tmp_path: Path) -> None:
    store = _legacy_store(tmp_path)
    assert_that(store.list_certificates(), equal_to([]))
    assert_that(store.ca_cert_path.is_file(), is_(True))
    assert_that((store.root / "ca.crt").exists(), is_(False))
    assert_that(store.lock_path.is_file(), is_(True))
    assert_that(_other_process_can_lock(store), is_(True))


def test_legacy_store_is_not_migrated_without_flock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _legacy_store(tmp_path)
    monkeypatch.setattr(sys, "platform", "win32")
    assert_that(calling(store.list_certificates), raises(TinyPkiError, "without a lock"))
    assert_that((store.root / "ca.crt").is_file(), is_(True))
    assert_that(store.ca_cert_path.exists(), is_(False))
