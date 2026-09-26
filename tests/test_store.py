"""Tests for the filesystem certificate store."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from hamcrest import assert_that, calling, equal_to, has_length, is_, none, not_none, raises

from tiny_pki import (
    generate_ca_certificate,
    generate_client_certificate,
    generate_crl,
    generate_server_certificate,
    get_certificate_expiry,
    get_certificate_fingerprint,
    get_certificate_serial_number,
)
from tiny_pki import store as store_module
from tiny_pki.store import CertificateStore, IssuedCertificate, require_store_path


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
    assert_that(entry.cert_path.startswith("clients/"), is_(True))
    assert_that(store.ca_cert_path.is_file(), is_(True))
    assert_that(store.ca_cert_path, equal_to(store.root / "ca" / "ca.crt"))


def test_ensure_layout_creates_typed_dirs(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "ca")
    store.ensure_layout()
    assert_that(store.ca_dir.is_dir(), is_(True))
    assert_that(store.clients_dir.is_dir(), is_(True))
    assert_that(store.servers_dir.is_dir(), is_(True))
    assert_that(store.bundles_dir.is_dir(), is_(True))
    assert_that(store.index_path.is_file(), is_(True))


def test_issue_paths_by_kind(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "ca")
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    store.write_ca(ca_cert, ca_key)

    client_pem, client_key = generate_client_certificate(ca_cert, ca_key, "alice", key_size=2048)
    client = store.add_certificate(
        common_name="alice",
        kind="client",
        serial_number=get_certificate_serial_number(client_pem),
        cert_pem=client_pem,
        key_pem=client_key,
        not_valid_after=get_certificate_expiry(client_pem),
        fingerprint=get_certificate_fingerprint(client_pem),
    )
    server_pem, server_key = generate_server_certificate(ca_cert, ca_key, "api.home", ["api.home"], key_size=2048)
    server = store.add_certificate(
        common_name="api.home",
        kind="server",
        serial_number=get_certificate_serial_number(server_pem),
        cert_pem=server_pem,
        key_pem=server_key,
        not_valid_after=get_certificate_expiry(server_pem),
        fingerprint=get_certificate_fingerprint(server_pem),
    )
    assert_that(client.cert_path.startswith("clients/"), is_(True))
    assert_that(server.cert_path.startswith("servers/"), is_(True))
    assert_that((store.root / client.cert_path).is_file(), is_(True))
    assert_that((store.root / server.cert_path).is_file(), is_(True))


def test_list_certificates_filters_kind_and_status(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "ca")
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    store.write_ca(ca_cert, ca_key)

    client_pem, client_key = generate_client_certificate(ca_cert, ca_key, "alice", key_size=2048)
    store.add_certificate(
        common_name="alice",
        kind="client",
        serial_number=get_certificate_serial_number(client_pem),
        cert_pem=client_pem,
        key_pem=client_key,
        not_valid_after=get_certificate_expiry(client_pem),
        fingerprint=get_certificate_fingerprint(client_pem),
    )
    server_pem, server_key = generate_server_certificate(ca_cert, ca_key, "api.home", ["api.home"], key_size=2048)
    store.add_certificate(
        common_name="api.home",
        kind="server",
        serial_number=get_certificate_serial_number(server_pem),
        cert_pem=server_pem,
        key_pem=server_key,
        not_valid_after=get_certificate_expiry(server_pem),
        fingerprint=get_certificate_fingerprint(server_pem),
    )
    store.mark_revoked("alice")

    assert_that(store.list_certificates(kind="client", status="active"), has_length(0))
    assert_that(store.list_certificates(kind="server", status="active"), has_length(1))
    assert_that(store.list_certificates(status="revoked"), has_length(1))
    assert_that(store.list_certificates(status="all"), has_length(2))
    assert_that(
        calling(store.list_certificates).with_args(status="bogus"),  # type: ignore[arg-type]
        raises(ValueError, "active"),
    )


def test_migrate_legacy_flat_layout(tmp_path: Path) -> None:
    root = tmp_path / "legacy"
    root.mkdir()
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    (root / "ca.crt").write_bytes(ca_cert)
    (root / "ca.key").write_bytes(ca_key)
    certs = root / "certs"
    certs.mkdir()
    client_pem, client_key = generate_client_certificate(ca_cert, ca_key, "alice", key_size=2048)
    serial = format(get_certificate_serial_number(client_pem), "x")
    (certs / f"alice-{serial}.crt").write_bytes(client_pem)
    (certs / f"alice-{serial}.key").write_bytes(client_key)
    server_pem, server_key = generate_server_certificate(ca_cert, ca_key, "api.home", ["api.home"], key_size=2048)
    server_serial = format(get_certificate_serial_number(server_pem), "x")
    (certs / f"api.home-{server_serial}.crt").write_bytes(server_pem)
    (certs / f"api.home-{server_serial}.key").write_bytes(server_key)
    revoked_pem, revoked_key = generate_client_certificate(ca_cert, ca_key, "oldbob", key_size=2048)
    revoked_serial = format(get_certificate_serial_number(revoked_pem), "x")
    (certs / f"oldbob-{revoked_serial}.crt").write_bytes(revoked_pem)
    (certs / f"oldbob-{revoked_serial}.key").write_bytes(revoked_key)
    revoked_at = "2020-01-01T00:00:00+00:00"
    (root / "index.json").write_text(
        "["
        "{"
        f'"common_name":"alice","kind":"client","serial_number":"{serial}",'
        f'"cert_path":"certs/alice-{serial}.crt","key_path":"certs/alice-{serial}.key",'
        f'"not_valid_after":"{get_certificate_expiry(client_pem).isoformat()}",'
        f'"fingerprint":"{get_certificate_fingerprint(client_pem)}","revoked_at":null'
        "},"
        "{"
        f'"common_name":"api.home","kind":"server","serial_number":"{server_serial}",'
        f'"cert_path":"certs/api.home-{server_serial}.crt",'
        f'"key_path":"certs/api.home-{server_serial}.key",'
        f'"not_valid_after":"{get_certificate_expiry(server_pem).isoformat()}",'
        f'"fingerprint":"{get_certificate_fingerprint(server_pem)}","revoked_at":null'
        "},"
        "{"
        f'"common_name":"oldbob","kind":"client","serial_number":"{revoked_serial}",'
        f'"cert_path":"certs/oldbob-{revoked_serial}.crt",'
        f'"key_path":"certs/oldbob-{revoked_serial}.key",'
        f'"not_valid_after":"{get_certificate_expiry(revoked_pem).isoformat()}",'
        f'"fingerprint":"{get_certificate_fingerprint(revoked_pem)}",'
        f'"revoked_at":"{revoked_at}"'
        "},"
        "{"
        '"common_name":"gone","kind":"client","serial_number":"dead",'
        '"cert_path":"","key_path":"",'
        '"not_valid_after":"2099-01-01T00:00:00+00:00",'
        '"fingerprint":"bb",'
        '"revoked_at":"2019-06-01T00:00:00+00:00"'
        "}"
        "]\n",
        encoding="utf-8",
    )

    store = CertificateStore(root)
    store.ensure_layout()

    assert_that(store.ca_cert_path.is_file(), is_(True))
    assert_that((root / "ca.crt").exists(), is_(False))
    assert_that((root / "certs").exists(), is_(False))
    entry = store.get_certificate("alice")
    assert_that(entry, is_(not_none()))
    live = cast(IssuedCertificate, entry)
    assert_that(live.cert_path.startswith("clients/"), is_(True))
    assert_that(live.key_path.startswith("clients/"), is_(True))
    assert_that(store.read_certificate_pem(live), equal_to(client_pem))
    assert_that(store.read_key_pem(live), equal_to(client_key))
    server = store.get_certificate("api.home")
    assert_that(server, is_(not_none()))
    server_entry = cast(IssuedCertificate, server)
    assert_that(server_entry.cert_path.startswith("servers/"), is_(True))
    assert_that(server_entry.key_path.startswith("servers/"), is_(True))
    assert_that((root / server_entry.cert_path).is_file(), is_(True))
    assert_that((root / server_entry.key_path).is_file(), is_(True))
    assert_that(store.read_key_pem(server_entry), equal_to(server_key))
    revoked_listed = store.list_certificates(status="revoked")
    assert_that(revoked_listed, has_length(2))
    assert_that({e.common_name for e in revoked_listed}, equal_to({"gone", "oldbob"}))
    gone = next(e for e in revoked_listed if e.common_name == "gone")
    assert_that(gone.cert_path, equal_to(""))
    assert_that(gone.revoked_at, equal_to("2019-06-01T00:00:00+00:00"))
    assert_that(store.revoked_entries(), has_length(2))
    assert_that(
        {serial for serial, _ in store.revoked_entries()},
        equal_to({int(revoked_serial, 16), int("dead", 16)}),
    )

    # First-touch has_ca/read_ca on a fresh flat store (no prior ensure_layout).
    root_untouched = tmp_path / "legacy-first-touch"
    root_untouched.mkdir()
    (root_untouched / "ca.crt").write_bytes(ca_cert)
    (root_untouched / "ca.key").write_bytes(ca_key)
    (root_untouched / "index.json").write_text("[]\n", encoding="utf-8")
    first_touch = CertificateStore(root_untouched)
    assert_that(first_touch.has_ca(), is_(True))
    assert_that(first_touch.read_ca()[0], equal_to(ca_cert))
    assert_that(first_touch.ca_cert_path.is_file(), is_(True))
    assert_that((root_untouched / "ca.crt").exists(), is_(False))
    assert_that(
        calling(first_touch.write_ca).with_args(*generate_ca_certificate(key_size=2048)),
        raises(ValueError, "already exists"),
    )

    # Leave a root CRL and reopen so read_crl migrates without other touches.
    root2 = tmp_path / "legacy-crl"
    root2.mkdir()
    (root2 / "ca.crt").write_bytes(ca_cert)
    (root2 / "ca.key").write_bytes(ca_key)
    (root2 / "crl.pem").write_bytes(b"legacy-crl")
    (root2 / "index.json").write_text("[]\n", encoding="utf-8")
    crl_store = CertificateStore(root2)
    assert_that(crl_store.read_crl(), equal_to(b"legacy-crl"))
    assert_that(crl_store.crl_path.is_file(), is_(True))
    assert_that((root2 / "crl.pem").exists(), is_(False))


def test_migrate_resumes_partial_layout(tmp_path: Path) -> None:
    """Index+leaves typed with CA PEMs still at root — migration finishes."""
    root = tmp_path / "partial"
    root.mkdir()
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    (root / "ca.crt").write_bytes(ca_cert)
    (root / "ca.key").write_bytes(ca_key)
    clients = root / "clients"
    clients.mkdir()
    client_pem, client_key = generate_client_certificate(ca_cert, ca_key, "alice", key_size=2048)
    serial = format(get_certificate_serial_number(client_pem), "x")
    (clients / f"alice-{serial}.crt").write_bytes(client_pem)
    (clients / f"alice-{serial}.key").write_bytes(client_key)
    ca_dir = root / "ca"
    ca_dir.mkdir()
    (ca_dir / "index.json").write_text(
        "["
        "{"
        f'"common_name":"alice","kind":"client","serial_number":"{serial}",'
        f'"cert_path":"clients/alice-{serial}.crt","key_path":"clients/alice-{serial}.key",'
        f'"not_valid_after":"{get_certificate_expiry(client_pem).isoformat()}",'
        f'"fingerprint":"{get_certificate_fingerprint(client_pem)}","revoked_at":null'
        "}"
        "]\n",
        encoding="utf-8",
    )
    store = CertificateStore(root)
    assert_that(store.has_ca(), is_(True))
    entry = store.get_certificate("alice")
    assert_that(entry, is_(not_none()))
    assert_that(cast(IssuedCertificate, entry).cert_path.startswith("clients/"), is_(True))
    assert_that(store.ca_cert_path.is_file(), is_(True))
    assert_that((root / "ca.crt").exists(), is_(False))

    # Mid-CA-move: ca.crt already under ca/, ca.key/crl.pem still at root.
    root_mid = tmp_path / "partial-mid-ca"
    root_mid.mkdir()
    (root_mid / "ca").mkdir()
    (root_mid / "ca" / "ca.crt").write_bytes(ca_cert)
    (root_mid / "ca.key").write_bytes(ca_key)
    (root_mid / "crl.pem").write_bytes(b"mid-crl")
    (root_mid / "ca" / "index.json").write_text("[]\n", encoding="utf-8")
    mid = CertificateStore(root_mid)
    assert_that(mid.has_ca(), is_(True))
    assert_that(mid.read_ca()[1], equal_to(ca_key))
    assert_that(mid.read_crl(), equal_to(b"mid-crl"))
    assert_that(mid.ca_key_path.is_file(), is_(True))
    assert_that((root_mid / "ca.key").exists(), is_(False))
    assert_that((root_mid / "crl.pem").exists(), is_(False))


def test_migrate_rejects_key_path_outside_certs(tmp_path: Path) -> None:
    root = tmp_path / "legacy"
    root.mkdir()
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    (root / "ca.crt").write_bytes(ca_cert)
    (root / "ca.key").write_bytes(ca_key)
    (root / "certs").mkdir()
    (root / "index.json").write_text(
        "["
        "{"
        '"common_name":"evil","kind":"client","serial_number":"1",'
        '"cert_path":"certs/evil-1.crt","key_path":"keys/evil.key",'
        '"not_valid_after":"2099-01-01T00:00:00+00:00",'
        '"fingerprint":"aa","revoked_at":null'
        "}"
        "]\n",
        encoding="utf-8",
    )
    store = CertificateStore(root)
    assert_that(calling(store.ensure_layout), raises(ValueError, "certs/"))


def test_migrate_rejects_path_traversal(tmp_path: Path) -> None:
    root = tmp_path / "legacy"
    root.mkdir()
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    (root / "ca.crt").write_bytes(ca_cert)
    (root / "ca.key").write_bytes(ca_key)
    outside = tmp_path / "outside.crt"
    outside.write_bytes(b"sentinel")
    (root / "index.json").write_text(
        "["
        "{"
        '"common_name":"evil","kind":"client","serial_number":"1",'
        '"cert_path":"certs/../../outside.crt","key_path":"certs/evil-1.key",'
        '"not_valid_after":"2099-01-01T00:00:00+00:00",'
        '"fingerprint":"aa","revoked_at":null'
        "}"
        "]\n",
        encoding="utf-8",
    )
    store = CertificateStore(root)
    assert_that(calling(store.ensure_layout), raises(ValueError, "relative path"))
    assert_that(outside.read_bytes(), equal_to(b"sentinel"))
    assert_that((root / "ca.crt").is_file(), is_(True))


def test_migrate_rejects_symlinked_ca_dir_with_no_index(tmp_path: Path) -> None:
    """No index.json anywhere skips the (now-protected) index migration branch

    entirely, leaving the flat-CA-material move as the only guard against a
    symlinked ``ca/`` — it must reject the same way, not follow the link.
    """
    root = tmp_path / "legacy"
    root.mkdir()
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    (root / "ca.crt").write_bytes(ca_cert)
    (root / "ca.key").write_bytes(ca_key)
    outside = tmp_path / "outside-ca-dir"
    outside.mkdir()
    (root / "ca").symlink_to(outside)
    store = CertificateStore(root)
    assert_that(calling(store.has_ca).with_args(), raises(ValueError, "symlink"))
    assert_that(list(outside.iterdir()), has_length(0))
    assert_that((root / "ca.crt").is_file(), is_(True))
    assert_that((root / "ca.key").is_file(), is_(True))


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


def test_write_ca_rejects_symlinked_ca_key(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "ca")
    store.ca_dir.mkdir(parents=True)
    outside = tmp_path / "outside.key"
    store.ca_key_path.symlink_to(outside)
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    assert_that(calling(store.write_ca).with_args(ca_cert, ca_key), raises(ValueError, "symlink"))
    assert_that(outside.exists(), is_(False))


def test_write_ca_rejects_symlinked_ca_cert(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "ca")
    store.ca_dir.mkdir(parents=True)
    outside = tmp_path / "outside.crt"
    outside.write_bytes(b"sentinel")
    store.ca_cert_path.symlink_to(outside)
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    assert_that(calling(store.write_ca).with_args(ca_cert, ca_key), raises(ValueError, "symlink"))
    assert_that(outside.read_bytes(), equal_to(b"sentinel"))


def test_write_ca_rejects_symlinked_ca_key_with_in_root_target(tmp_path: Path) -> None:
    """A symlink whose *target* stays inside the store root must still be rejected.

    ``_path_under_root`` alone would accept this (the resolved path lands
    under root), and ``_open_new_file`` would never see the original
    symlink either (it opens the already-resolved path) — only checking
    the unresolved path up front catches it.
    """
    store = CertificateStore(tmp_path / "ca")
    store.ca_dir.mkdir(parents=True)
    evil = store.ca_dir / "evil"
    evil.write_bytes(b"attacker-owned")
    store.ca_key_path.symlink_to(evil)
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    assert_that(calling(store.write_ca).with_args(ca_cert, ca_key), raises(ValueError, "symlink"))
    assert_that(evil.read_bytes(), equal_to(b"attacker-owned"))


def test_write_crl_rejects_symlinked_crl_path(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "ca")
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    store.write_ca(ca_cert, ca_key)
    outside = tmp_path / "outside.pem"
    outside.write_bytes(b"sentinel")
    store.crl_path.symlink_to(outside)
    crl_pem = generate_crl(ca_cert, ca_key, [])
    assert_that(calling(store.write_crl).with_args(crl_pem), raises(ValueError, "symlink"))
    assert_that(outside.read_bytes(), equal_to(b"sentinel"))


def test_write_ca_rejects_symlinked_ca_directory(tmp_path: Path) -> None:
    """A symlink at ca/ itself (not just at ca.key) must not redirect writes."""
    store = CertificateStore(tmp_path / "ca")
    store.root.mkdir(parents=True)
    outside = tmp_path / "outside-ca-dir"
    outside.mkdir()
    (store.root / "ca").symlink_to(outside)
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    assert_that(calling(store.write_ca).with_args(ca_cert, ca_key), raises(ValueError, "symlink"))
    assert_that(list(outside.iterdir()), has_length(0))


def test_write_ca_rejects_symlinked_ca_directory_with_in_root_target(tmp_path: Path) -> None:
    """A ca/ symlink whose target is itself still inside the store root must be rejected too.

    ``_path_under_root`` alone would accept this (the resolved path lands
    under root, just via a different subtree), so the parent-component
    check has to happen against the *unresolved* path, not the resolved
    one.
    """
    store = CertificateStore(tmp_path / "ca")
    store.root.mkdir(parents=True)
    evil = store.root / "evil"
    evil.mkdir()
    (evil / "ca.key").write_bytes(b"attacker-owned")
    (store.root / "ca").symlink_to(evil)
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    assert_that(calling(store.write_ca).with_args(ca_cert, ca_key), raises(ValueError, "symlink"))
    assert_that((evil / "ca.key").read_bytes(), equal_to(b"attacker-owned"))


def test_add_certificate_rejects_symlinked_index(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "ca")
    ca_cert, ca_key = generate_ca_certificate(key_size=2048)
    store.write_ca(ca_cert, ca_key)
    outside = tmp_path / "outside-index.json"
    outside.write_bytes(store.index_path.read_bytes())
    store.index_path.unlink()
    store.index_path.symlink_to(outside)
    sentinel = outside.read_bytes()
    client_cert, client_key = generate_client_certificate(ca_cert, ca_key, "alice", key_size=2048)
    assert_that(
        calling(store.add_certificate).with_args(
            common_name="alice",
            kind="client",
            serial_number=get_certificate_serial_number(client_cert),
            cert_pem=client_cert,
            key_pem=client_key,
            not_valid_after=get_certificate_expiry(client_cert),
            fingerprint=get_certificate_fingerprint(client_cert),
        ),
        raises(ValueError, "symlink"),
    )
    assert_that(outside.read_bytes(), equal_to(sentinel))


def test_write_plain_rejects_symlink_directly(tmp_path: Path) -> None:
    """Every ``_path_under_root``-backed call site passes an already-resolved
    path, so nothing else in the suite reaches ``write_file_atomic``'s own
    ``is_symlink()`` guard. Exercise it directly so that backstop can't be
    deleted without a test failing.
    """
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"sentinel")
    link = tmp_path / "link"
    link.symlink_to(outside)
    assert_that(
        calling(store_module._write_plain).with_args(link, b"x"),  # pyright: ignore[reportPrivateUsage]
        raises(ValueError, "symlink"),
    )
    assert_that(outside.read_bytes(), equal_to(b"sentinel"))


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
    revoked_listed = store.list_certificates(status="revoked")
    assert_that(revoked_listed, has_length(1))
    assert_that(revoked_listed[0].common_name, equal_to("bob"))
    assert_that(revoked_listed[0].cert_path, equal_to(""))


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
        '"cert_path":"../outside.crt","key_path":"clients/x.key",'
        '"not_valid_after":"2099-01-01T00:00:00+00:00","fingerprint":"f","revoked_at":null}]\n',
        encoding="utf-8",
    )
    assert_that(calling(store.list_certificates), raises(ValueError, "relative path"))
    store.index_path.write_text(
        '[{"common_name":"evil","kind":"client","serial_number":"1",'
        f'"cert_path":"{tmp_path / "abs.crt"}","key_path":"clients/x.key",'
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
    store.clients_dir.mkdir(exist_ok=True)
    link = store.clients_dir / "alice-1.crt"
    link.symlink_to(outside)
    (store.clients_dir / "alice-1.key").symlink_to(tmp_path / "outside.key")
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
