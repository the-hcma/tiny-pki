"""Inspection takes PEM or DER and exposes URI SANs and a peer's identity (issue #167)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import ipaddress
import ssl
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from hamcrest import assert_that, calling, contains_string, empty, equal_to, is_, not_, raises

from tiny_pki import (
    CertificateIdentity,
    TinyPkiError,
    check_certificate,
    generate_ca_certificate,
    generate_client_certificate,
    generate_server_certificate,
    get_certificate_expiry,
    get_certificate_fingerprint,
    get_certificate_identity,
    get_certificate_issuer,
    get_certificate_metadata,
    get_certificate_sans,
    get_certificate_serial_number,
    get_certificate_subject,
    get_certificate_uris,
    is_certificate_self_signed,
)

_CA = generate_ca_certificate("Inspect DER CA", key_type="ec-p256")
_SERVER = generate_server_certificate(*_CA, "localhost", ["localhost", "127.0.0.1"], key_type="ec-p256")
_CLIENT = generate_client_certificate(*_CA, "alice", key_type="ec-p256")


def _der(pem: bytes) -> bytes:
    return x509.load_pem_x509_certificate(pem).public_bytes(serialization.Encoding.DER)


def _with_sans(names: list[x509.GeneralName] | None) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "device-1")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Elsewhere CA")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
    )
    if names is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


_INSPECTORS: list[Callable[[bytes], Any]] = [
    get_certificate_expiry,
    get_certificate_fingerprint,
    get_certificate_identity,
    get_certificate_issuer,
    get_certificate_metadata,
    get_certificate_sans,
    get_certificate_serial_number,
    get_certificate_subject,
    get_certificate_uris,
    is_certificate_self_signed,
]


@pytest.mark.parametrize("inspector", _INSPECTORS, ids=lambda f: f.__name__)
@pytest.mark.parametrize("pem", [_CA[0], _SERVER[0], _CLIENT[0]], ids=["ca", "server", "client"])
def test_every_inspector_reads_pem_and_der_alike(inspector: Callable[[bytes], Any], pem: bytes) -> None:
    assert_that(inspector(_der(pem)), equal_to(inspector(pem)))


def test_check_certificate_reads_der_for_the_leaf_and_the_ca() -> None:
    from_pem = check_certificate(_SERVER[0], ca_cert_pem=_CA[0])
    from_der = check_certificate(_der(_SERVER[0]), ca_cert_pem=_der(_CA[0]))
    assert_that(
        (from_der.status, from_der.subject, from_der.serial_number),
        equal_to((from_pem.status, from_pem.subject, from_pem.serial_number)),
    )


def test_uris_come_in_certificate_order_next_to_dns_and_ip_sans() -> None:
    pem = _with_sans(
        [
            x509.DNSName("device-1.home"),
            x509.UniformResourceIdentifier("spiffe://example.home/device/phone-1"),
            x509.IPAddress(ipaddress.ip_address("192.168.1.20")),
            x509.UniformResourceIdentifier("https://example.home/devices/1"),
        ]
    )
    assert_that(
        get_certificate_uris(pem),
        equal_to(["spiffe://example.home/device/phone-1", "https://example.home/devices/1"]),
    )
    assert_that(get_certificate_sans(pem), equal_to(["device-1.home", "192.168.1.20"]))
    identity = get_certificate_identity(_der(pem))
    assert_that(identity.common_name, equal_to("device-1"))
    assert_that(identity.dns_names, equal_to(("device-1.home",)))
    assert_that(identity.ip_addresses, equal_to(("192.168.1.20",)))
    assert_that(identity.uris, equal_to(("spiffe://example.home/device/phone-1", "https://example.home/devices/1")))


def test_der_containing_a_pem_header_in_a_uri_is_still_read_as_der() -> None:
    uri = "https://example.test/-----BEGIN CERTIFICATE-----"
    pem = _with_sans([x509.UniformResourceIdentifier(uri)])
    der = _der(pem)
    assert_that(b"-----BEGIN" in der, is_(True))
    assert_that(get_certificate_uris(der), equal_to([uri]))
    assert_that(get_certificate_identity(der), equal_to(get_certificate_identity(pem)))


def test_no_sans_gives_empty_uris_and_identity_tuples() -> None:
    for pem in (_with_sans(None), _CLIENT[0]):
        assert_that(get_certificate_uris(pem), is_(empty()))
        identity = get_certificate_identity(pem)
        assert_that((identity.dns_names, identity.ip_addresses, identity.uris), equal_to(((), (), ())))


def test_identity_carries_serial_and_fingerprint() -> None:
    identity = get_certificate_identity(_SERVER[0])
    assert_that(
        identity,
        equal_to(
            CertificateIdentity(
                common_name="localhost",
                dns_names=("localhost",),
                ip_addresses=("127.0.0.1",),
                uris=(),
                serial_number=get_certificate_serial_number(_SERVER[0]),
                fingerprint=get_certificate_fingerprint(_SERVER[0]),
            )
        ),
    )


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"", "got empty input"),
        (b"\x30\x03\x02\x01\x07not-a-certificate", "bytes that are not DER"),
        (b"-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----\n", "PEM data"),
        (b"-----BEGIN CERTIFICATE REQUEST-----\nbm9wZQ==\n-----END CERTIFICATE REQUEST-----\n", "PEM data"),
    ],
)
def test_bad_input_names_both_formats_without_echoing_it(data: bytes, expected: str) -> None:
    assert_that(
        calling(get_certificate_identity).with_args(data),
        raises(TinyPkiError, "Expected a PEM or DER X.509 certificate"),
    )
    with pytest.raises(TinyPkiError) as raised:
        get_certificate_subject(data)
    assert_that(str(raised.value), contains_string(expected))
    assert_that(str(raised.value), not_(contains_string("not-a-certificate")))
    assert_that(str(raised.value), not_(contains_string("bm90IGEgY2VydA")))


def _write(directory: Path, name: str, data: bytes) -> Path:
    path = directory / name
    path.write_bytes(data)
    return path


def _pump(client: ssl.SSLObject, server: ssl.SSLObject, wires: tuple[ssl.MemoryBIO, ...]) -> None:
    client_out, server_in, server_out, client_in = wires
    for _ in range(50):
        done = 0
        for side in (client, server):
            try:
                side.do_handshake()
                done += 1
            except ssl.SSLWantReadError:
                pass
        server_in.write(client_out.read())
        client_in.write(server_out.read())
        if done == 2:
            return
    raise AssertionError("TLS handshake did not finish")


def test_identity_of_the_peer_certificate_from_a_real_handshake(tmp_path: Path) -> None:
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(_write(tmp_path, "s.crt", _SERVER[0]), _write(tmp_path, "s.key", _SERVER[1]))
    server_ctx.load_verify_locations(cadata=_CA[0].decode())
    server_ctx.verify_mode = ssl.CERT_REQUIRED
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.load_cert_chain(_write(tmp_path, "c.crt", _CLIENT[0]), _write(tmp_path, "c.key", _CLIENT[1]))
    client_ctx.load_verify_locations(cadata=_CA[0].decode())
    wires = tuple(ssl.MemoryBIO() for _ in range(4))
    client_out, server_in, server_out, client_in = wires
    client = client_ctx.wrap_bio(client_in, client_out, server_hostname="localhost")
    server = server_ctx.wrap_bio(server_in, server_out, server_side=True)
    _pump(client, server, wires)

    peer_der = server.getpeercert(binary_form=True)
    assert peer_der is not None
    identity = get_certificate_identity(peer_der)
    assert_that(identity.common_name, equal_to("alice"))
    assert_that(identity.serial_number, equal_to(get_certificate_serial_number(_CLIENT[0])))
    assert_that(get_certificate_subject(peer_der), equal_to("alice"))
