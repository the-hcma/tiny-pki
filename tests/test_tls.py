"""tiny_pki.tls: SSLContext objects for mutual TLS from PEM bytes (issue #166)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import asyncio
import os
import ssl
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from hamcrest import assert_that, calling, contains_string, equal_to, is_, not_, raises

from tiny_pki import TinyPkiError, generate_ca_certificate, get_certificate_identity
from tiny_pki._keys import load_private_key
from tiny_pki.store import CertificateStore
from tiny_pki.tls import client_context, server_context

_CA = generate_ca_certificate("TLS CA", key_type="ec-p256")
_OTHER_CA = generate_ca_certificate("Other CA", key_type="ec-p256")


@dataclass
class _Pki:
    store: CertificateStore
    server: tuple[bytes, bytes]
    client: tuple[bytes, bytes]
    ca_pem: bytes


def _pair(store: CertificateStore, cn: str) -> tuple[bytes, bytes]:
    entry = store.get_certificate(cn)
    assert entry is not None
    return store.read_certificate_pem(entry), (store.root / entry.key_path).read_bytes()


@pytest.fixture
def pki(tmp_path: Path) -> _Pki:
    store = CertificateStore(tmp_path / "store")
    store.write_ca(*_CA)
    store.publish_crl()
    store.issue_server("localhost", ["localhost", "127.0.0.1"], key_type="ec-p256")
    store.issue_client("alice", key_type="ec-p256")
    return _Pki(store, _pair(store, "localhost"), _pair(store, "alice"), store.read_ca_certificate())


@dataclass
class _Outcome:
    reply: bytes | None
    error: BaseException | None
    peer_cn: str | None
    version: str | None


async def _exchange(server_ctx: ssl.SSLContext, client_ctx: ssl.SSLContext, server_hostname: str) -> _Outcome:
    seen: dict[str, Any] = {}

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        ssl_object = writer.get_extra_info("ssl_object")
        der = ssl_object.getpeercert(binary_form=True)
        seen["cn"] = get_certificate_identity(der).common_name if der else None
        seen["version"] = ssl_object.version()
        await reader.readline()
        writer.write(b"hello " + (seen["cn"] or "anonymous").encode() + b"\n")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=server_ctx)
    port = server.sockets[0].getsockname()[1]
    reply: bytes | None = None
    error: BaseException | None = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", port, ssl=client_ctx, server_hostname=server_hostname), 10
        )
        writer.write(b"hi\n")
        await writer.drain()
        reply = await asyncio.wait_for(reader.readline(), 10) or None
        writer.close()
    except (OSError, ssl.SSLError, asyncio.IncompleteReadError) as exc:
        error = exc
    finally:
        server.close()
        await server.wait_closed()
    return _Outcome(reply, error, seen.get("cn"), seen.get("version"))


def _handshake(server_ctx: ssl.SSLContext, client_ctx: ssl.SSLContext, server_hostname: str = "localhost") -> _Outcome:
    return asyncio.run(_exchange(server_ctx, client_ctx, server_hostname))


def test_mutual_tls_handshake(pki: _Pki) -> None:
    outcome = _handshake(server_context(*pki.server, pki.ca_pem), client_context(*pki.client, pki.ca_pem))
    assert_that(outcome.error, is_(None))
    assert_that(outcome.reply, equal_to(b"hello alice\n"))
    assert_that(outcome.peer_cn, equal_to("alice"))


def test_a_client_without_a_certificate_is_refused_by_default(pki: _Pki) -> None:
    anonymous = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    anonymous.load_verify_locations(cadata=pki.ca_pem.decode())
    outcome = _handshake(server_context(*pki.server, pki.ca_pem), anonymous)
    assert_that(outcome.reply, is_(None))
    assert_that(outcome.peer_cn, is_(None))


def test_optional_client_certificates_admit_anonymous_clients(pki: _Pki) -> None:
    anonymous = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    anonymous.load_verify_locations(cadata=pki.ca_pem.decode())
    outcome = _handshake(server_context(*pki.server, pki.ca_pem, client_cert="optional"), anonymous)
    assert_that(outcome.reply, equal_to(b"hello anonymous\n"))


def test_a_client_from_another_ca_is_refused(pki: _Pki) -> None:
    other = CertificateStore(pki.store.root.parent / "other")
    other.write_ca(*_OTHER_CA)
    other.publish_crl()
    other.issue_client("mallory", key_type="ec-p256")
    outcome = _handshake(server_context(*pki.server, pki.ca_pem), client_context(*_pair(other, "mallory"), pki.ca_pem))
    assert_that(outcome.reply, is_(None))
    assert_that(outcome.peer_cn, is_(None))


@pytest.mark.parametrize("max_version", [None, ssl.TLSVersion.TLSv1_2])
def test_a_revoked_client_is_refused_with_a_crl(pki: _Pki, max_version: ssl.TLSVersion | None) -> None:
    pki.store.revoke("alice")
    crl = pki.store.read_crl()
    assert crl is not None
    server_ctx = server_context(*pki.server, pki.ca_pem, crl_pem=crl, max_tls_version=max_version)
    outcome = _handshake(server_ctx, client_context(*pki.client, pki.ca_pem))
    assert_that(outcome.reply, is_(None))
    assert_that(outcome.peer_cn, is_(None))


@pytest.mark.parametrize("crl_check", ["leaf", "chain"])
def test_a_live_client_passes_the_crl_check(pki: _Pki, crl_check: str) -> None:
    pki.store.issue_client("bob", key_type="ec-p256")
    pki.store.revoke("bob")
    crl = pki.store.read_crl()
    assert crl is not None
    server_ctx = server_context(*pki.server, pki.ca_pem, crl_pem=crl, crl_check=crl_check)  # type: ignore[arg-type]
    outcome = _handshake(server_ctx, client_context(*pki.client, pki.ca_pem))
    assert_that(outcome.reply, equal_to(b"hello alice\n"))


def test_the_crl_is_loaded_into_the_context(pki: _Pki) -> None:
    crl = pki.store.read_crl()
    assert crl is not None
    stats = server_context(*pki.server, pki.ca_pem, crl_pem=crl).cert_store_stats()
    assert_that(stats, equal_to({"x509": 1, "crl": 1, "x509_ca": 1}))


def test_system_cas_are_never_trusted(pki: _Pki) -> None:
    assert_that(server_context(*pki.server, pki.ca_pem).cert_store_stats()["x509_ca"], equal_to(1))
    assert_that(client_context(*pki.client, pki.ca_pem).cert_store_stats()["x509_ca"], equal_to(1))


def test_hostname_checking(pki: _Pki) -> None:
    server_ctx = server_context(*pki.server, pki.ca_pem)
    strict = _handshake(server_ctx, client_context(*pki.client, pki.ca_pem), server_hostname="wrong.example")
    assert_that(strict.reply, is_(None))
    assert_that(strict.error, not_(None))
    lax = client_context(*pki.client, pki.ca_pem, server_hostname_check=False)
    assert_that(_handshake(server_ctx, lax, server_hostname="wrong.example").reply, equal_to(b"hello alice\n"))


def test_tls_versions(pki: _Pki) -> None:
    server_ctx = server_context(*pki.server, pki.ca_pem, max_tls_version=ssl.TLSVersion.TLSv1_2)
    assert_that(server_ctx.minimum_version, equal_to(ssl.TLSVersion.TLSv1_2))
    outcome = _handshake(server_ctx, client_context(*pki.client, pki.ca_pem))
    assert_that(outcome.version, equal_to("TLSv1.2"))
    assert_that(client_context(*pki.client, pki.ca_pem).minimum_version, equal_to(ssl.TLSVersion.TLSv1_2))


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"crl_check": "leaf"}, "Expected crl_pem with crl_check='leaf'"),
        ({"crl_check": "chain"}, "Expected crl_pem with crl_check='chain'"),
        ({"crl_check": "all"}, "Expected crl_check in"),
        ({"client_cert": "maybe"}, "Expected client_cert in"),
        ({"max_tls_version": ssl.TLSVersion.TLSv1_1}, "Expected max_tls_version TLSv1_2 or later"),
    ],
)
def test_server_context_rejects_bad_options(pki: _Pki, kwargs: dict[str, Any], message: str) -> None:
    assert_that(calling(server_context).with_args(*pki.server, pki.ca_pem, **kwargs), raises(TinyPkiError, message))


def test_server_context_rejects_crl_options_that_would_skip_the_check(pki: _Pki) -> None:
    crl = pki.store.read_crl()
    assert_that(
        calling(server_context).with_args(*pki.server, pki.ca_pem, crl_pem=crl, client_cert="none"),
        raises(TinyPkiError, "client_cert 'optional' or 'required' with crl_pem"),
    )
    assert_that(
        calling(server_context).with_args(*pki.server, pki.ca_pem, crl_pem=crl, crl_check="none"),
        raises(TinyPkiError, "crl_check 'leaf' or 'chain' with crl_pem"),
    )
    assert_that(
        calling(server_context).with_args(*pki.server, pki.ca_pem, crl_pem=pki.ca_pem),
        raises(TinyPkiError, "PEM CRLs"),
    )


def test_mismatched_and_encrypted_keys_are_refused(pki: _Pki) -> None:
    assert_that(
        calling(server_context).with_args(pki.server[0], pki.client[1], pki.ca_pem),
        raises(TinyPkiError, "match the certificate"),
    )
    encrypted = load_private_key(pki.client[1]).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"fake-test-password-123"),
    )
    assert_that(
        calling(client_context).with_args(pki.client[0], encrypted, pki.ca_pem),
        raises(TinyPkiError, "unencrypted"),
    )


def test_malformed_input_is_refused_without_echoing_it(pki: _Pki) -> None:
    secret = b"-----BEGIN PRIVATE KEY-----\nc2VjcmV0LWtleS1tYXRlcmlhbA==\n-----END PRIVATE KEY-----\n"
    with pytest.raises(TinyPkiError) as excinfo:
        client_context(pki.client[0], secret, pki.ca_pem)
    assert_that(str(excinfo.value), not_(contains_string("c2VjcmV0")))
    assert_that(
        calling(client_context).with_args(b"not a cert", pki.client[1], pki.ca_pem), raises(TinyPkiError, "cert_pem")
    )
    assert_that(calling(client_context).with_args(*pki.client, b"not a cert"), raises(TinyPkiError, "ca_cert_pem"))


def test_temporary_files_are_private_and_removed(pki: _Pki, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    modes: list[tuple[str, int]] = []
    original = ssl.SSLContext.load_cert_chain

    def spy(self: ssl.SSLContext, certfile: str, keyfile: str | None = None, password: Any = None) -> None:
        for path in (Path(certfile).parent, Path(certfile), Path(keyfile or certfile)):
            modes.append((path.name, stat.S_IMODE(os.stat(path).st_mode)))
        original(self, certfile, keyfile)

    monkeypatch.setattr(ssl.SSLContext, "load_cert_chain", spy)
    crl = pki.store.read_crl()
    server_context(*pki.server, pki.ca_pem, crl_pem=crl)
    client_context(*pki.client, pki.ca_pem)
    assert_that([mode for _, mode in modes], equal_to([0o700, 0o600, 0o600] * 2))
    assert_that(list(scratch.iterdir()), equal_to([]))

    def failing(self: ssl.SSLContext, certfile: str, keyfile: str | None = None, password: Any = None) -> None:
        raise ssl.SSLError(1, "boom")

    monkeypatch.setattr(ssl.SSLContext, "load_cert_chain", failing)
    assert_that(calling(client_context).with_args(*pki.client, pki.ca_pem), raises(TinyPkiError, "OpenSSL accepts"))
    assert_that(list(scratch.iterdir()), equal_to([]))


def test_import_tiny_pki_does_not_import_tls() -> None:
    code = "import sys, tiny_pki; assert 'tiny_pki.tls' not in sys.modules, sorted(sys.modules)"
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=False)
    assert_that(result.returncode, equal_to(0), result.stderr)
