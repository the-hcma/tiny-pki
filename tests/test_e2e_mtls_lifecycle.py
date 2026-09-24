"""End-to-end mTLS lifecycle coverage for issue #21 user stories."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import socket
import ssl
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import time_machine
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID
from hamcrest import (
    any_of,
    assert_that,
    contains_inanyorder,
    contains_string,
    equal_to,
    greater_than,
    has_item,
    has_length,
    instance_of,
    is_,
    is_not,
    none,
    not_none,
)
from pytest import CaptureFixture

from tiny_pki import (
    generate_ca_certificate,
    generate_client_certificate,
    generate_crl,
    generate_pkcs12,
    generate_server_certificate,
    get_certificate_expiry,
    get_certificate_fingerprint,
    get_certificate_sans,
    get_certificate_serial_number,
    get_certificate_subject,
    is_certificate_self_signed,
)
from tiny_pki.cli.main import main
from tiny_pki.store import CertificateStore


@dataclass(frozen=True)
class _TlsMaterial:
    ca_cert: bytes
    ca_key: bytes
    client_cert: bytes
    client_key: bytes
    crl: bytes
    server_cert: bytes
    server_key: bytes


def _assert_crl_signed_by_ca(crl_pem: bytes, ca_cert_pem: bytes) -> None:
    crl = x509.load_pem_x509_crl(crl_pem)
    public_key = x509.load_pem_x509_certificate(ca_cert_pem).public_key()
    assert_that(public_key, instance_of(RSAPublicKey))
    assert_that(crl.is_signature_valid(public_key), is_(True))  # type: ignore[arg-type]


def _assert_leaf_identity(
    *,
    cert_pem: bytes,
    expected_cn: str,
    expected_sans: list[str] | None = None,
    server_auth: bool,
) -> None:
    """Issued leaf matches the requested CN/SAN/EKU and exposes serial + fingerprint."""
    assert_that(get_certificate_subject(cert_pem), equal_to(expected_cn))
    if expected_sans is not None:
        assert_that(get_certificate_sans(cert_pem), contains_inanyorder(*expected_sans))
        assert_that(get_certificate_sans(cert_pem), has_item(expected_sans[0]))
    assert_that(get_certificate_serial_number(cert_pem), greater_than(0))
    fingerprint = get_certificate_fingerprint(cert_pem)
    parts = fingerprint.split(":")
    assert_that(parts, has_length(32))
    assert_that(all(len(part) == 2 for part in parts), is_(True))
    cert = x509.load_pem_x509_certificate(cert_pem)
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    if server_auth:
        assert_that(list(eku), has_item(ExtendedKeyUsageOID.SERVER_AUTH))
    else:
        assert_that(list(eku), has_item(ExtendedKeyUsageOID.CLIENT_AUTH))


def _client_context(
    *,
    client_cert: Path,
    client_key: Path,
    trust: Path,
    check_crl: bool,
    check_hostname: bool = True,
) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = check_hostname
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=str(trust))
    if check_crl:
        ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
    ctx.load_cert_chain(client_cert, client_key)
    return ctx


def _handshake(
    *,
    server_ctx: ssl.SSLContext,
    client_ctx: ssl.SSLContext,
    server_hostname: str = "localhost",
) -> tuple[bool, list[str]]:
    """Return ``(both_sides_ok, error_messages)``.

    Both peers must complete without ``OSError`` (includes ``ssl.SSLError``).
    A server thread that is still alive after join is treated as failure so
    TLS 1.3 client-first completion cannot mask a server-side CRL reject.
    """
    ready = threading.Event()
    port_holder: list[int] = []
    errors: list[str] = []
    server_ok = False

    def serve() -> None:
        nonlocal server_ok
        try:
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port_holder.append(listener.getsockname()[1])
                listener.listen(1)
                ready.set()
                conn, _peer = listener.accept()
                with server_ctx.wrap_socket(conn, server_side=True) as tls:
                    _ = tls.recv(1)
                    server_ok = True
        except OSError as exc:
            errors.append(f"server: {exc}")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    assert_that(ready.wait(5.0), is_(True))
    port = port_holder[0]
    client_ok = False
    try:
        with (
            socket.create_connection(("127.0.0.1", port), timeout=5.0) as raw,
            client_ctx.wrap_socket(raw, server_hostname=server_hostname) as tls,
        ):
            tls.sendall(b"x")
            client_ok = True
    except OSError as exc:
        errors.append(f"client: {exc}")
    thread.join(5.0)
    if thread.is_alive():
        errors.append("server: handshake thread still alive after join")
    both_ok = client_ok and server_ok and not errors
    return both_ok, errors


def _issue_library_pair(*, client_cn: str = "alice", server_cn: str = "localhost") -> _TlsMaterial:
    sans = ["localhost", "127.0.0.1"]
    ca_cert, ca_key = generate_ca_certificate("E2E CA", key_size=2048)
    server_cert, server_key = generate_server_certificate(
        ca_cert,
        ca_key,
        server_cn,
        sans,
        key_size=2048,
    )
    client_cert, client_key = generate_client_certificate(ca_cert, ca_key, client_cn, key_size=2048)
    crl = generate_crl(ca_cert, ca_key, [])
    return _TlsMaterial(
        ca_cert=ca_cert,
        ca_key=ca_key,
        client_cert=client_cert,
        client_key=client_key,
        crl=crl,
        server_cert=server_cert,
        server_key=server_key,
    )


def _pem_from_private_key(key: object) -> bytes:
    assert_that(key, instance_of(object))
    return key.private_bytes(  # type: ignore[union-attr]
        Encoding.PEM,
        PrivateFormat.TraditionalOpenSSL,
        NoEncryption(),
    )


def _run_cli(store: Path, *words: str, capsys: CaptureFixture[str]) -> tuple[str, str]:
    main(["--store", str(store), "--color", "never", *words])
    captured = capsys.readouterr()
    return captured.out, captured.err


def _serial_revoked(cert_pem: bytes, crl_pem: bytes) -> bool:
    cert = x509.load_pem_x509_certificate(cert_pem)
    crl = x509.load_pem_x509_crl(crl_pem)
    return crl.get_revoked_certificate_by_serial_number(cert.serial_number) is not None


def _server_context(
    *,
    server_cert: Path,
    server_key: Path,
    trust: Path,
    check_crl: bool,
) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_cert_chain(server_cert, server_key)
    ctx.load_verify_locations(cafile=str(trust))
    if check_crl:
        ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
    return ctx


def _trust_bundle(directory: Path, name: str, ca_cert: bytes, crl_pem: bytes) -> Path:
    path = directory / name
    path.write_bytes(ca_cert + crl_pem)
    return path


def _write_pair(directory: Path, stem: str, cert_pem: bytes, key_pem: bytes) -> tuple[Path, Path]:
    cert_path = directory / f"{stem}.crt"
    key_path = directory / f"{stem}.key"
    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(key_pem)
    return cert_path, key_path


def test_cli_store_mtls_lifecycle(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    """CLI store path: issue CA/client/server, handshake, revoke both ways.

    - ``init`` / ``create`` emit the requested CN, SANs, serial, and fingerprint
    - Empty CRL still allows a mutual TLS handshake
    - Revoking the client makes the server reject that cert
    - Re-issuing the same CN keeps the old serial on the CRL; the new cert works
    - Revoking the server makes the client reject that cert
    """
    store_root = tmp_path / "store"
    files = tmp_path / "tls"
    files.mkdir()

    # Issue a CA plus client and server identities
    _run_cli(store_root, "init", "--cn", "CLI E2E CA", "--key-size", "2048", capsys=capsys)
    _run_cli(
        store_root,
        "create",
        "server",
        "localhost",
        "--san",
        "localhost",
        "--san",
        "127.0.0.1",
        "--key-size",
        "2048",
        capsys=capsys,
    )
    _run_cli(store_root, "create", "client", "alice", "--key-size", "2048", capsys=capsys)

    store = CertificateStore(store_root)
    ca_cert, ca_key = store.read_ca()
    server_entry = store.get_certificate("localhost")
    client_entry = store.get_certificate("alice")
    assert_that(server_entry, is_(not_none()))
    assert_that(client_entry, is_(not_none()))
    assert server_entry is not None
    assert client_entry is not None
    assert_that(server_entry.revoked_at, is_(none()))
    assert_that(client_entry.revoked_at, is_(none()))

    server_pem = store.read_certificate_pem(server_entry)
    server_key_pem = store.read_key_pem(server_entry)
    client_pem = store.read_certificate_pem(client_entry)
    client_key_pem = store.read_key_pem(client_entry)
    _assert_leaf_identity(
        cert_pem=server_pem,
        expected_cn="localhost",
        expected_sans=["localhost", "127.0.0.1"],
        server_auth=True,
    )
    _assert_leaf_identity(cert_pem=client_pem, expected_cn="alice", server_auth=False)

    crl_pem = store.read_crl()
    assert_that(crl_pem, is_(not_none()))
    assert crl_pem is not None

    server_cert, server_key = _write_pair(files, "server", server_pem, server_key_pem)
    client_cert, client_key = _write_pair(files, "client", client_pem, client_key_pem)
    trust = _trust_bundle(files, "trust.pem", ca_cert, crl_pem)

    # Mutual TLS still works with an empty CRL
    ok, errors = _handshake(
        server_ctx=_server_context(
            server_cert=server_cert,
            server_key=server_key,
            trust=trust,
            check_crl=True,
        ),
        client_ctx=_client_context(
            client_cert=client_cert,
            client_key=client_key,
            trust=trust,
            check_crl=True,
        ),
    )
    assert_that(ok, is_(True), f"CLI baseline handshake failed: {errors}")

    # Revoke the client — server must reject it via CRL
    _run_cli(store_root, "revoke", "alice", capsys=capsys)
    store = CertificateStore(store_root)
    crl_after = store.read_crl()
    assert_that(crl_after, is_(not_none()))
    assert crl_after is not None
    assert_that(_serial_revoked(client_pem, crl_after), is_(True))
    trust_rev = _trust_bundle(files, "trust-rev.pem", ca_cert, crl_after)

    ok_rev, rev_errors = _handshake(
        server_ctx=_server_context(
            server_cert=server_cert,
            server_key=server_key,
            trust=trust_rev,
            check_crl=True,
        ),
        client_ctx=_client_context(
            client_cert=client_cert,
            client_key=client_key,
            trust=trust,
            check_crl=True,
        ),
    )
    assert_that(ok_rev, is_(False))
    assert_that("".join(rev_errors).lower(), contains_string("revok"))

    # Re-issue the same CN; old serial stays revoked, then revoke the server
    _run_cli(store_root, "create", "client", "alice", "--key-size", "2048", capsys=capsys)
    store = CertificateStore(store_root)
    reissued = store.get_certificate("alice")
    assert_that(reissued, is_(not_none()))
    assert reissued is not None
    assert_that(reissued.revoked_at, is_(none()))
    reissued_pem = store.read_certificate_pem(reissued)
    reissued_key = store.read_key_pem(reissued)
    old_serial = get_certificate_serial_number(client_pem)
    new_serial = get_certificate_serial_number(reissued_pem)
    assert_that(new_serial, is_not(equal_to(old_serial)))
    assert_that(get_certificate_subject(reissued_pem), equal_to("alice"))
    crl_reissue = store.read_crl()
    assert_that(crl_reissue, is_(not_none()))
    assert crl_reissue is not None
    assert_that(_serial_revoked(client_pem, crl_reissue), is_(True))
    assert_that(_serial_revoked(reissued_pem, crl_reissue), is_(False))

    alice2_cert, alice2_key = _write_pair(files, "alice2", reissued_pem, reissued_key)
    trust_reissue = _trust_bundle(files, "trust-reissue.pem", ca_cert, crl_reissue)
    ok_reissue, reissue_errors = _handshake(
        server_ctx=_server_context(
            server_cert=server_cert,
            server_key=server_key,
            trust=trust_reissue,
            check_crl=True,
        ),
        client_ctx=_client_context(
            client_cert=alice2_cert,
            client_key=alice2_key,
            trust=trust_reissue,
            check_crl=True,
        ),
    )
    assert_that(ok_reissue, is_(True), f"re-issued alice should succeed: {reissue_errors}")

    _run_cli(store_root, "revoke", "localhost", capsys=capsys)
    store = CertificateStore(store_root)
    crl_server = store.read_crl()
    assert_that(crl_server, is_(not_none()))
    assert crl_server is not None
    assert_that(_serial_revoked(server_pem, crl_server), is_(True))
    trust_server_rev = _trust_bundle(files, "trust-server-rev.pem", ca_cert, crl_server)

    ok_server_rev, server_rev_errors = _handshake(
        server_ctx=_server_context(
            server_cert=server_cert,
            server_key=server_key,
            trust=trust_reissue,
            check_crl=True,
        ),
        client_ctx=_client_context(
            client_cert=alice2_cert,
            client_key=alice2_key,
            trust=trust_server_rev,
            check_crl=True,
        ),
    )
    assert_that(ok_server_rev, is_(False))
    assert_that("".join(server_rev_errors).lower(), contains_string("revok"))
    assert_that(len(ca_key), is_not(equal_to(0)))


def test_foreign_crl_is_not_signed_by_our_ca() -> None:
    """A CRL signed by another CA must not verify under ours."""
    ca_cert, ca_key = generate_ca_certificate("CRL CA", key_size=2048)
    other_ca, other_key = generate_ca_certificate("Other CRL CA", key_size=2048)
    client_cert, _client_key = generate_client_certificate(ca_cert, ca_key, "alice", key_size=2048)
    serial = get_certificate_serial_number(client_cert)
    foreign_crl = generate_crl(other_ca, other_key, [(serial, datetime.now(UTC))])
    crl = x509.load_pem_x509_crl(foreign_crl)
    public_key = x509.load_pem_x509_certificate(ca_cert).public_key()
    assert_that(public_key, instance_of(RSAPublicKey))
    assert_that(crl.is_signature_valid(public_key), is_(False))  # type: ignore[arg-type]


def test_library_mtls_lifecycle_with_crl(tmp_path: Path) -> None:
    """Library path: issue certs, handshake, revoke client then server.

    - Issued leaves carry the requested CN/SAN/EKU plus serial and fingerprint
    - Empty CRL still allows mutual TLS
    - Wrong CA as trust root fails; hostname/SAN mismatch fails
    - Revoked client is rejected; a new client still works
    - Revoking the server keeps prior serials on the CRL; a new server works
    """
    material = _issue_library_pair()
    server_sans = ["localhost", "127.0.0.1"]

    # Issued identities match what we asked for
    assert_that(is_certificate_self_signed(material.ca_cert), is_(True))
    assert_that(is_certificate_self_signed(material.client_cert), is_(False))
    assert_that(is_certificate_self_signed(material.server_cert), is_(False))
    _assert_leaf_identity(
        cert_pem=material.server_cert,
        expected_cn="localhost",
        expected_sans=server_sans,
        server_auth=True,
    )
    _assert_leaf_identity(cert_pem=material.client_cert, expected_cn="alice", server_auth=False)
    _assert_crl_signed_by_ca(material.crl, material.ca_cert)

    server_cert, server_key = _write_pair(tmp_path, "server", material.server_cert, material.server_key)
    client_cert, client_key = _write_pair(tmp_path, "client", material.client_cert, material.client_key)
    trust_live = _trust_bundle(tmp_path, "trust-live.pem", material.ca_cert, material.crl)

    # Mutual TLS still works with an empty CRL
    ok, errors = _handshake(
        server_ctx=_server_context(
            server_cert=server_cert,
            server_key=server_key,
            trust=trust_live,
            check_crl=True,
        ),
        client_ctx=_client_context(
            client_cert=client_cert,
            client_key=client_key,
            trust=trust_live,
            check_crl=True,
        ),
    )
    assert_that(ok, is_(True), f"baseline handshake failed: {errors}")

    # Trusting the wrong CA must fail the handshake
    other_ca, _other_key = generate_ca_certificate("Other CA", key_size=2048)
    other_trust = tmp_path / "other-ca.pem"
    other_trust.write_bytes(other_ca)
    ok_wrong, wrong_errors = _handshake(
        server_ctx=_server_context(
            server_cert=server_cert,
            server_key=server_key,
            trust=trust_live,
            check_crl=True,
        ),
        client_ctx=_client_context(
            client_cert=client_cert,
            client_key=client_key,
            trust=other_trust,
            check_crl=False,
        ),
    )
    assert_that(ok_wrong, is_(False))
    assert_that("".join(wrong_errors).lower(), contains_string("certificate"))

    # Connecting with a hostname absent from the server SAN must fail
    ok_san, san_errors = _handshake(
        server_ctx=_server_context(
            server_cert=server_cert,
            server_key=server_key,
            trust=trust_live,
            check_crl=True,
        ),
        client_ctx=_client_context(
            client_cert=client_cert,
            client_key=client_key,
            trust=trust_live,
            check_crl=True,
        ),
        server_hostname="not-the-server.example",
    )
    assert_that(ok_san, is_(False))
    assert_that("".join(san_errors).lower(), contains_string("hostname"))

    # Revoke the client — server rejects it; a fresh client still works
    client_serial = get_certificate_serial_number(material.client_cert)
    revoked_client_crl = generate_crl(
        material.ca_cert,
        material.ca_key,
        [(client_serial, datetime.now(UTC))],
    )
    _assert_crl_signed_by_ca(revoked_client_crl, material.ca_cert)
    assert_that(_serial_revoked(material.client_cert, revoked_client_crl), is_(True))
    assert_that(_serial_revoked(material.server_cert, revoked_client_crl), is_(False))

    trust_rev_client = _trust_bundle(tmp_path, "trust-rev-client.pem", material.ca_cert, revoked_client_crl)
    ok_rev_client, rev_client_errors = _handshake(
        server_ctx=_server_context(
            server_cert=server_cert,
            server_key=server_key,
            trust=trust_rev_client,
            check_crl=True,
        ),
        client_ctx=_client_context(
            client_cert=client_cert,
            client_key=client_key,
            trust=trust_live,
            check_crl=True,
        ),
    )
    assert_that(ok_rev_client, is_(False))
    assert_that("".join(rev_client_errors).lower(), contains_string("revok"))

    new_client_cert, new_client_key = generate_client_certificate(
        material.ca_cert,
        material.ca_key,
        "bob",
        key_size=2048,
    )
    _assert_leaf_identity(cert_pem=new_client_cert, expected_cn="bob", server_auth=False)
    assert_that(_serial_revoked(new_client_cert, revoked_client_crl), is_(False))
    bob_cert, bob_key = _write_pair(tmp_path, "bob", new_client_cert, new_client_key)
    ok_bob, bob_errors = _handshake(
        server_ctx=_server_context(
            server_cert=server_cert,
            server_key=server_key,
            trust=trust_rev_client,
            check_crl=True,
        ),
        client_ctx=_client_context(
            client_cert=bob_cert,
            client_key=bob_key,
            trust=trust_rev_client,
            check_crl=True,
        ),
    )
    assert_that(ok_bob, is_(True), f"new client should succeed: {bob_errors}")

    # Revoke the server (CRL keeps both serials); a new server succeeds
    server_serial = get_certificate_serial_number(material.server_cert)
    revoked_server_crl = generate_crl(
        material.ca_cert,
        material.ca_key,
        [
            (client_serial, datetime.now(UTC)),
            (server_serial, datetime.now(UTC)),
        ],
    )
    assert_that(_serial_revoked(material.server_cert, revoked_server_crl), is_(True))
    assert_that(_serial_revoked(new_client_cert, revoked_server_crl), is_(False))
    assert_that(_serial_revoked(material.client_cert, revoked_server_crl), is_(True))

    trust_rev_server = _trust_bundle(tmp_path, "trust-rev-server.pem", material.ca_cert, revoked_server_crl)
    ok_rev_server, rev_server_errors = _handshake(
        server_ctx=_server_context(
            server_cert=server_cert,
            server_key=server_key,
            trust=trust_rev_client,
            check_crl=True,
        ),
        client_ctx=_client_context(
            client_cert=bob_cert,
            client_key=bob_key,
            trust=trust_rev_server,
            check_crl=True,
        ),
    )
    assert_that(ok_rev_server, is_(False))
    assert_that("".join(rev_server_errors).lower(), contains_string("revok"))

    new_server_cert, new_server_key = generate_server_certificate(
        material.ca_cert,
        material.ca_key,
        "localhost",
        server_sans,
        key_size=2048,
    )
    _assert_leaf_identity(
        cert_pem=new_server_cert,
        expected_cn="localhost",
        expected_sans=server_sans,
        server_auth=True,
    )
    assert_that(_serial_revoked(new_server_cert, revoked_server_crl), is_(False))
    new_srv_cert, new_srv_key = _write_pair(tmp_path, "server2", new_server_cert, new_server_key)
    ok_new_server, new_server_errors = _handshake(
        server_ctx=_server_context(
            server_cert=new_srv_cert,
            server_key=new_srv_key,
            trust=trust_rev_server,
            check_crl=True,
        ),
        client_ctx=_client_context(
            client_cert=bob_cert,
            client_key=bob_key,
            trust=trust_rev_server,
            check_crl=True,
        ),
    )
    assert_that(ok_new_server, is_(True), f"new server should succeed: {new_server_errors}")


def test_pkcs12_roundtrip_handshakes(tmp_path: Path) -> None:
    """Export a client PKCS#12, reload it, and complete mutual TLS.

    Matches the CLI ``export p12`` handoff: bundle cert+key+CA, load with the
    password, then handshake with CRL checking enabled.
    """
    material = _issue_library_pair()
    password = b"change-me-e2e"
    p12_bytes = generate_pkcs12(
        material.client_cert,
        material.client_key,
        material.ca_cert,
        "alice",
        password,
    )
    key, cert, additional_certs = pkcs12.load_key_and_certificates(p12_bytes, password)
    assert_that(key, is_(not_none()))
    assert_that(cert, is_(not_none()))
    assert key is not None
    assert cert is not None
    loaded_cert = cert.public_bytes(Encoding.PEM)
    loaded_key = _pem_from_private_key(key)
    assert_that(get_certificate_subject(loaded_cert), equal_to("alice"))
    loaded_serial = get_certificate_serial_number(loaded_cert)
    assert_that(loaded_serial, equal_to(get_certificate_serial_number(material.client_cert)))
    assert_that(
        get_certificate_fingerprint(loaded_cert),
        equal_to(get_certificate_fingerprint(material.client_cert)),
    )
    assert_that(additional_certs, has_length(1))

    server_cert, server_key = _write_pair(tmp_path, "server", material.server_cert, material.server_key)
    client_cert, client_key = _write_pair(tmp_path, "p12-client", loaded_cert, loaded_key)
    trust = _trust_bundle(tmp_path, "trust.pem", material.ca_cert, material.crl)
    ok, errors = _handshake(
        server_ctx=_server_context(
            server_cert=server_cert,
            server_key=server_key,
            trust=trust,
            check_crl=True,
        ),
        client_ctx=_client_context(
            client_cert=client_cert,
            client_key=client_key,
            trust=trust,
            check_crl=True,
        ),
    )
    assert_that(ok, is_(True), f"PKCS#12 client handshake failed: {errors}")


def test_expired_client_leaf_is_rejected(tmp_path: Path) -> None:
    """Expired client leaf fails mTLS; a still-valid client from the same CA works.

    Issue the short-lived client under a frozen past clock so its ``notAfter`` is
    already behind wall-clock when OpenSSL verifies (stdlib TLS uses OS time).
    """
    past = datetime.now(UTC) - timedelta(days=10)
    with time_machine.travel(past, tick=False):
        ca_cert, ca_key = generate_ca_certificate("Expiry CA", key_size=2048, validity_days=3650)
        expired_client, expired_key = generate_client_certificate(
            ca_cert,
            ca_key,
            "stale",
            key_size=2048,
            validity_days=1,
        )

    assert_that(get_certificate_expiry(expired_client), is_not(none()))
    assert_that(get_certificate_expiry(expired_client) < datetime.now(UTC), is_(True))

    server_pem, server_key_pem = generate_server_certificate(
        ca_cert,
        ca_key,
        "localhost",
        ["localhost", "127.0.0.1"],
        key_size=2048,
    )
    fresh_client, fresh_key = generate_client_certificate(ca_cert, ca_key, "fresh", key_size=2048)
    crl = generate_crl(ca_cert, ca_key, [])

    server_cert, server_key = _write_pair(tmp_path, "server", server_pem, server_key_pem)
    stale_cert, stale_key = _write_pair(tmp_path, "stale", expired_client, expired_key)
    fresh_cert, fresh_key_path = _write_pair(tmp_path, "fresh", fresh_client, fresh_key)
    trust = _trust_bundle(tmp_path, "trust.pem", ca_cert, crl)

    ok_stale, stale_errors = _handshake(
        server_ctx=_server_context(
            server_cert=server_cert,
            server_key=server_key,
            trust=trust,
            check_crl=True,
        ),
        client_ctx=_client_context(
            client_cert=stale_cert,
            client_key=stale_key,
            trust=trust,
            check_crl=True,
        ),
    )
    assert_that(ok_stale, is_(False), f"expired client should fail: {stale_errors}")
    joined = "".join(stale_errors).lower()
    assert_that(
        joined,
        any_of(contains_string("expir"), contains_string("certificate verify failed")),
    )

    ok_fresh, fresh_errors = _handshake(
        server_ctx=_server_context(
            server_cert=server_cert,
            server_key=server_key,
            trust=trust,
            check_crl=True,
        ),
        client_ctx=_client_context(
            client_cert=fresh_cert,
            client_key=fresh_key_path,
            trust=trust,
            check_crl=True,
        ),
    )
    assert_that(ok_fresh, is_(True), f"fresh client should succeed: {fresh_errors}")
