"""Tests for the filesystem certificate store."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from hamcrest import assert_that, calling, equal_to, has_length, is_, none, not_none, raises

from tiny_pki import (
    generate_ca_certificate,
    generate_client_certificate,
    get_certificate_expiry,
    get_certificate_fingerprint,
    get_certificate_serial_number,
)
from tiny_pki.store import CertificateStore, require_store_path


def test_require_store_path_rejects_empty() -> None:
    assert_that(calling(require_store_path).with_args(None), raises(ValueError, "explicit store"))
    assert_that(calling(require_store_path).with_args("  "), raises(ValueError, "explicit store"))
    assert_that(calling(require_store_path).with_args(Path("")), raises(ValueError, "explicit store"))


def test_certificate_store_rejects_empty_root() -> None:
    assert_that(calling(CertificateStore).with_args(""), raises(ValueError, "non-empty store"))
    assert_that(calling(CertificateStore).with_args("  "), raises(ValueError, "non-empty store"))
    assert_that(calling(CertificateStore).with_args("."), raises(ValueError, "non-empty store"))
    assert_that(calling(CertificateStore).with_args(Path("")), raises(ValueError, "non-empty store"))


def test_write_ca_and_issue_client(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "ca")
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    store.write_ca(ca_cert, ca_key)
    assert_that(store.has_ca(), is_(True))
    assert_that(oct(store.ca_key_path.stat().st_mode & 0o777), equal_to("0o600"))

    cert_pem, key_pem = generate_client_certificate(ca_cert, ca_key, "alice", key_size=2048)
    entry = store.add_certificate(
        common_name="alice",
        kind="client",
        serial_number=get_certificate_serial_number(cert_pem),
        cert_pem=cert_pem,
        key_pem=key_pem,
        not_valid_after=get_certificate_expiry(cert_pem),
        fingerprint=get_certificate_fingerprint(cert_pem),
    )
    assert_that(store.get_certificate("alice"), equal_to(entry))
    assert_that(store.get_certificate("ALICE"), equal_to(entry))
    assert_that(store.get_certificate(" alice "), equal_to(entry))
    assert_that(store.list_certificates(), equal_to([entry]))
    assert_that(store.read_certificate_pem(entry), equal_to(cert_pem))
    assert_that(store.read_key_pem(entry), equal_to(key_pem))
    assert_that(oct((store.root / entry.key_path).stat().st_mode & 0o777), equal_to("0o600"))
    assert_that(entry.serial_number in entry.cert_path, is_(True))


def test_write_ca_refuses_overwrite_without_force(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "ca")
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    store.write_ca(ca_cert, ca_key)
    other_cert, other_key = generate_ca_certificate(key_size=2048)
    assert_that(
        calling(store.write_ca).with_args(other_cert, other_key),
        raises(ValueError, "already exists"),
    )
    store.write_ca(other_cert, other_key, force=True)
    assert_that(store.read_ca()[0], equal_to(other_cert))
    assert_that(store.read_ca()[1], equal_to(other_key))
    assert_that(oct(store.ca_key_path.stat().st_mode & 0o777), equal_to("0o600"))


def test_crl_roundtrip(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "ca")
    assert_that(store.read_crl(), is_(none()))
    store.write_crl(b"crl-bytes")
    assert_that(store.crl_path.is_file(), is_(True))
    assert_that(store.read_crl(), equal_to(b"crl-bytes"))


def test_write_bundle_mode(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "ca")
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    store.write_ca(ca_cert, ca_key)
    cert_pem, key_pem = generate_client_certificate(ca_cert, ca_key, "alice", key_size=2048)
    entry = store.add_certificate(
        common_name="alice",
        kind="client",
        serial_number=get_certificate_serial_number(cert_pem),
        cert_pem=cert_pem,
        key_pem=key_pem,
        not_valid_after=get_certificate_expiry(cert_pem),
        fingerprint=get_certificate_fingerprint(cert_pem),
    )
    path = store.write_bundle("alice", b"p12-bytes")
    assert_that(path, equal_to(store.bundles_dir / f"alice-{entry.serial_number}.p12"))
    assert_that(path.read_bytes(), equal_to(b"p12-bytes"))
    assert_that(oct(path.stat().st_mode & 0o777), equal_to("0o600"))


def test_revoke_and_delete_tombstone(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "ca")
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    store.write_ca(ca_cert, ca_key)
    cert_pem, key_pem = generate_client_certificate(ca_cert, ca_key, "bob", key_size=2048)
    store.add_certificate(
        common_name="bob",
        kind="client",
        serial_number=get_certificate_serial_number(cert_pem),
        cert_pem=cert_pem,
        key_pem=key_pem,
        not_valid_after=get_certificate_expiry(cert_pem),
        fingerprint=get_certificate_fingerprint(cert_pem),
    )
    assert_that(
        calling(store.delete_certificate).with_args("bob"),
        raises(ValueError, "still active"),
    )
    when = datetime(2020, 1, 1, tzinfo=UTC)
    revoked = store.mark_revoked("bob", revoked_at=when)
    assert_that(revoked.revoked_at, equal_to("2020-01-01T00:00:00+00:00"))
    # Idempotent revoke preserves original timestamp.
    again = store.mark_revoked("bob")
    assert_that(again.revoked_at, equal_to(revoked.revoked_at))
    entries = store.revoked_entries()
    assert_that(entries, has_length(1))
    serial, revoked_when = entries[0]
    assert_that(serial, equal_to(int(revoked.serial_number, 16)))
    assert_that(revoked_when, equal_to(when))

    cert_file = store.root / revoked.cert_path
    key_file = store.root / revoked.key_path
    tombstone = store.delete_certificate("bob")
    assert_that(tombstone.cert_path, equal_to(""))
    assert_that(store.get_certificate("bob"), is_(none()))
    assert_that(cert_file.exists(), is_(False))
    assert_that(key_file.exists(), is_(False))
    assert_that(
        calling(store.read_certificate_pem).with_args(tombstone),
        raises(FileNotFoundError),
    )
    # Tombstone keeps serial for CRL regeneration.
    assert_that(store.revoked_entries(), has_length(1))
    assert_that(store.list_certificates(), has_length(0))


def test_delete_force_active(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "ca")
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    store.write_ca(ca_cert, ca_key)
    cert_pem, key_pem = generate_client_certificate(ca_cert, ca_key, "dave", key_size=2048)
    entry = store.add_certificate(
        common_name="dave",
        kind="client",
        serial_number=get_certificate_serial_number(cert_pem),
        cert_pem=cert_pem,
        key_pem=key_pem,
        not_valid_after=get_certificate_expiry(cert_pem),
        fingerprint=get_certificate_fingerprint(cert_pem),
    )
    cert_file = store.root / entry.cert_path
    key_file = store.root / entry.key_path
    deleted = store.delete_certificate("dave", force=True)
    assert_that(deleted.common_name, equal_to("dave"))
    assert_that(store.get_certificate("dave"), is_(none()))
    assert_that(cert_file.exists(), is_(False))
    assert_that(key_file.exists(), is_(False))
    assert_that(store.revoked_entries(), has_length(0))


def test_index_path_traversal_rejected(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "ca")
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    store.write_ca(ca_cert, ca_key)
    store.index_path.write_text(
        '[{"common_name":"evil","kind":"client","serial_number":"1",'
        '"cert_path":"../outside.crt","key_path":"certs/x.key",'
        '"not_valid_after":"2099-01-01T00:00:00+00:00","fingerprint":"f","revoked_at":null}]\n',
        encoding="utf-8",
    )
    assert_that(calling(store.list_certificates), raises(ValueError, "relative path"))
    store.index_path.write_text(
        '[{"common_name":"evil","kind":"client","serial_number":"1",'
        f'"cert_path":"{tmp_path / "abs.crt"}","key_path":"certs/x.key",'
        '"not_valid_after":"2099-01-01T00:00:00+00:00","fingerprint":"f","revoked_at":null}]\n',
        encoding="utf-8",
    )
    assert_that(calling(store.list_certificates), raises(ValueError))


def test_lookup_by_serial(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "ca")
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    store.write_ca(ca_cert, ca_key)
    cert_pem, key_pem = generate_client_certificate(ca_cert, ca_key, "carol", key_size=2048)
    serial = get_certificate_serial_number(cert_pem)
    store.add_certificate(
        common_name="carol",
        kind="client",
        serial_number=serial,
        cert_pem=cert_pem,
        key_pem=key_pem,
        not_valid_after=get_certificate_expiry(cert_pem),
        fingerprint=get_certificate_fingerprint(cert_pem),
    )
    found = store.get_certificate(format(serial, "x"))
    assert_that(found, is_(not_none()))
    assert_that(found.common_name if found else None, equal_to("carol"))
    revoked = store.mark_revoked(f"0x{format(serial, 'x')}")
    assert_that(revoked.common_name, equal_to("carol"))
    assert_that(revoked.revoked_at, is_(not_none()))


def test_missing_index_with_ca_raises(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "ca")
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    store.write_ca(ca_cert, ca_key)
    store.index_path.unlink()
    assert_that(calling(store.list_certificates), raises(FileNotFoundError, "index.json"))
    assert_that(calling(store.write_crl).with_args(b"x"), raises(FileNotFoundError, "index.json"))


def test_reissue_keeps_revoked_tombstone(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "ca")
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    store.write_ca(ca_cert, ca_key)
    first_pem, first_key = generate_client_certificate(ca_cert, ca_key, "alice", key_size=2048)
    first = store.add_certificate(
        common_name="alice",
        kind="client",
        serial_number=get_certificate_serial_number(first_pem),
        cert_pem=first_pem,
        key_pem=first_key,
        not_valid_after=get_certificate_expiry(first_pem),
        fingerprint=get_certificate_fingerprint(first_pem),
    )
    first_cert = store.root / first.cert_path
    first_key_path = store.root / first.key_path
    store.mark_revoked("alice")
    store.delete_certificate("alice")
    second_pem, second_key = generate_client_certificate(ca_cert, ca_key, "alice", key_size=2048)
    second = store.add_certificate(
        common_name="alice",
        kind="client",
        serial_number=get_certificate_serial_number(second_pem),
        cert_pem=second_pem,
        key_pem=second_key,
        not_valid_after=get_certificate_expiry(second_pem),
        fingerprint=get_certificate_fingerprint(second_pem),
    )
    assert_that(second.serial_number != first.serial_number, is_(True))
    revoked = store.revoked_entries()
    assert_that(revoked, has_length(1))
    assert_that(revoked[0][0], equal_to(int(first.serial_number, 16)))
    assert_that(store.get_certificate("alice"), equal_to(second))
    assert_that(first_cert.exists(), is_(False))
    assert_that(first_key_path.exists(), is_(False))


def test_reissue_live_auto_revokes_superseded(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "ca")
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    store.write_ca(ca_cert, ca_key)
    first_pem, first_key = generate_client_certificate(ca_cert, ca_key, "alice", key_size=2048)
    first = store.add_certificate(
        common_name="alice",
        kind="client",
        serial_number=get_certificate_serial_number(first_pem),
        cert_pem=first_pem,
        key_pem=first_key,
        not_valid_after=get_certificate_expiry(first_pem),
        fingerprint=get_certificate_fingerprint(first_pem),
    )
    first_cert = store.root / first.cert_path
    second_pem, second_key = generate_client_certificate(ca_cert, ca_key, "alice", key_size=2048)
    second = store.add_certificate(
        common_name="alice",
        kind="client",
        serial_number=get_certificate_serial_number(second_pem),
        cert_pem=second_pem,
        key_pem=second_key,
        not_valid_after=get_certificate_expiry(second_pem),
        fingerprint=get_certificate_fingerprint(second_pem),
    )
    assert_that(store.get_certificate("alice"), equal_to(second))
    assert_that(first_cert.exists(), is_(False))
    revoked = store.revoked_entries()
    assert_that(revoked, has_length(1))
    assert_that(revoked[0][0], equal_to(int(first.serial_number, 16)))


def test_add_certificate_same_serial_is_idempotent(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "ca")
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    store.write_ca(ca_cert, ca_key)
    cert_pem, key_pem = generate_client_certificate(ca_cert, ca_key, "alice", key_size=2048)
    serial = get_certificate_serial_number(cert_pem)
    first = store.add_certificate(
        common_name="alice",
        kind="client",
        serial_number=serial,
        cert_pem=cert_pem,
        key_pem=key_pem,
        not_valid_after=get_certificate_expiry(cert_pem),
        fingerprint=get_certificate_fingerprint(cert_pem),
    )
    again = store.add_certificate(
        common_name="alice",
        kind="client",
        serial_number=serial,
        cert_pem=cert_pem,
        key_pem=key_pem,
        not_valid_after=get_certificate_expiry(cert_pem),
        fingerprint=get_certificate_fingerprint(cert_pem),
    )
    assert_that(again.serial_number, equal_to(first.serial_number))
    assert_that(store.read_key_pem(again), equal_to(key_pem))
    assert_that(store.revoked_entries(), has_length(0))


def test_get_certificate_prefers_live_after_revoke_reissue(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "ca")
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    store.write_ca(ca_cert, ca_key)
    first_pem, first_key = generate_client_certificate(ca_cert, ca_key, "alice", key_size=2048)
    first = store.add_certificate(
        common_name="alice",
        kind="client",
        serial_number=get_certificate_serial_number(first_pem),
        cert_pem=first_pem,
        key_pem=first_key,
        not_valid_after=get_certificate_expiry(first_pem),
        fingerprint=get_certificate_fingerprint(first_pem),
    )
    store.mark_revoked("alice")
    # Revoked entry still has paths; re-issue without delete.
    second_pem, second_key = generate_client_certificate(ca_cert, ca_key, "alice", key_size=2048)
    second = store.add_certificate(
        common_name="alice",
        kind="client",
        serial_number=get_certificate_serial_number(second_pem),
        cert_pem=second_pem,
        key_pem=second_key,
        not_valid_after=get_certificate_expiry(second_pem),
        fingerprint=get_certificate_fingerprint(second_pem),
    )
    assert_that(store.get_certificate("alice"), equal_to(second))
    assert_that(store.get_certificate(first.serial_number), is_(not_none()))
    store.mark_revoked("alice")
    # Both serials revoked (still with paths); CN lookup returns a revoked match.
    found = store.get_certificate("alice")
    assert_that(found, is_(not_none()))
    assert_that(found.revoked_at if found else None, is_(not_none()))
    assert_that(store.revoked_entries(), has_length(2))


def test_write_bundle_rejects_non_hex_serial(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "ca")
    assert_that(
        calling(store.write_bundle).with_args("alice", b"p12", serial_number="../x"),
        raises(ValueError, "hex serial"),
    )


def test_missing_identity_raises_keyerror(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "ca")
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    store.write_ca(ca_cert, ca_key)
    assert_that(calling(store.mark_revoked).with_args("nobody"), raises(KeyError))
    assert_that(calling(store.delete_certificate).with_args("nobody"), raises(KeyError))
    assert_that(calling(store.write_bundle).with_args("nobody", b"p12"), raises(KeyError))


def test_refuse_reissue_of_revoked_serial(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "ca")
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    store.write_ca(ca_cert, ca_key)
    cert_pem, key_pem = generate_client_certificate(ca_cert, ca_key, "alice", key_size=2048)
    serial = get_certificate_serial_number(cert_pem)
    store.add_certificate(
        common_name="alice",
        kind="client",
        serial_number=serial,
        cert_pem=cert_pem,
        key_pem=key_pem,
        not_valid_after=get_certificate_expiry(cert_pem),
        fingerprint=get_certificate_fingerprint(cert_pem),
    )
    store.mark_revoked("alice")
    assert_that(
        calling(store.add_certificate).with_args(
            common_name="alice",
            kind="client",
            serial_number=serial,
            cert_pem=cert_pem,
            key_pem=key_pem,
            not_valid_after=get_certificate_expiry(cert_pem),
            fingerprint=get_certificate_fingerprint(cert_pem),
        ),
        raises(ValueError, "already revoked"),
    )


def test_add_certificate_rejects_symlink_escape(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "ca")
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    store.write_ca(ca_cert, ca_key)
    outside = tmp_path / "outside.crt"
    outside.write_bytes(b"sentinel")
    store.certs_dir.mkdir(exist_ok=True)
    link = store.certs_dir / "alice-1.crt"
    link.symlink_to(outside)
    (store.certs_dir / "alice-1.key").symlink_to(tmp_path / "outside.key")
    assert_that(
        calling(store.add_certificate).with_args(
            common_name="alice",
            kind="client",
            serial_number=1,
            cert_pem=b"cert",
            key_pem=b"key",
            not_valid_after=datetime(2099, 1, 1, tzinfo=UTC),
            fingerprint="f",
        ),
        raises(ValueError),
    )
    assert_that(outside.read_bytes(), equal_to(b"sentinel"))


def test_add_certificate_rejects_invalid_kind(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "ca")
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    store.write_ca(ca_cert, ca_key)
    assert_that(
        calling(store.add_certificate).with_args(
            common_name="alice",
            kind="clientt",  # type: ignore[arg-type]
            serial_number=1,
            cert_pem=b"cert",
            key_pem=b"key",
            not_valid_after=datetime(2099, 1, 1, tzinfo=UTC),
            fingerprint="f",
        ),
        raises(ValueError, "client' or 'server"),
    )


def test_store_path_strips_whitespace(tmp_path: Path) -> None:
    target = tmp_path / "ca"
    store = CertificateStore(f"  {target}  ")
    assert_that(store.root, equal_to(target.resolve()))
    assert_that(require_store_path(f"  {target}  "), equal_to(target.resolve()))
