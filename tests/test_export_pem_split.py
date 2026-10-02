"""export pem --cert-out / --key-out / --ca-out (issue #169)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import asyncio
import os
import ssl
import stat
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from hamcrest import assert_that, contains_string, equal_to, is_
from pytest import CaptureFixture

from tiny_pki import _fsutil, generate_ca_certificate
from tiny_pki.cli.main import main
from tiny_pki.store import CertificateStore

_CA = generate_ca_certificate("Export CA", key_type="ec-p256")


def _run(store: Path, *words: str, capsys: CaptureFixture[str], expect_ok: bool = True) -> tuple[str, str]:
    argv = ["--store", str(store), "--color", "never", *words]
    if expect_ok:
        main(argv)
    else:
        with pytest.raises(SystemExit):
            main(argv)
    captured = capsys.readouterr()
    return captured.out, captured.err


def _csr() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "laptop")]))
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
    )


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


@pytest.fixture
def store(tmp_path: Path) -> CertificateStore:
    store = CertificateStore(tmp_path / "store")
    store.write_ca(*_CA)
    store.publish_crl()
    store.issue_server("localhost", ["localhost", "127.0.0.1"], key_type="ec-p256")
    store.issue_client("alice", key_type="ec-p256")
    store.sign_client_csr("laptop", _csr())
    return store


@pytest.fixture
def out(tmp_path: Path) -> Path:
    directory = tmp_path / "out"
    directory.mkdir()
    return directory


def _split(store: CertificateStore, out: Path, name: str, capsys: CaptureFixture[str]) -> tuple[Path, Path, Path]:
    cert, key, ca = out / f"{name}.crt", out / f"{name}.key", out / "ca.crt"
    args = ("export", "pem", name, "--cert-out", str(cert), "--key-out", str(key), "--ca-out", str(ca))
    _run(store.root, *args, capsys=capsys)
    return cert, key, ca


def test_split_export_writes_three_files_with_their_modes(
    store: CertificateStore, out: Path, capsys: CaptureFixture[str]
) -> None:
    cert, key, ca = _split(store, out, "alice", capsys)
    entry = store.get_certificate("alice")
    assert entry is not None
    assert_that(cert.read_bytes(), equal_to(store.read_certificate_pem(entry)))
    assert_that(key.read_bytes(), equal_to(store.read_key_pem(entry)))
    assert_that(ca.read_bytes(), equal_to((store.public_dir / "ca.crt").read_bytes()))
    assert_that([_mode(cert), _mode(key), _mode(ca)], equal_to([0o644, 0o600, 0o644]))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_cert_chain(cert, key)
    context.load_verify_locations(ca)
    assert_that(sorted(p.name for p in out.iterdir()), equal_to(["alice.crt", "alice.key", "ca.crt"]))


async def _exchange(server_ctx: ssl.SSLContext, client_ctx: ssl.SSLContext) -> bytes:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
        cn = x509.load_der_x509_certificate(der).subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        await reader.readline()
        writer.write(f"hello {cn}\n".encode())
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=server_ctx)
    port = server.sockets[0].getsockname()[1]
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", port, ssl=client_ctx, server_hostname="localhost"), 10
        )
        writer.write(b"hi\n")
        await writer.drain()
        reply = await asyncio.wait_for(reader.readline(), 10)
        writer.close()
        return reply
    finally:
        server.close()
        await server.wait_closed()


def test_split_files_complete_a_mutual_tls_handshake(
    store: CertificateStore, out: Path, capsys: CaptureFixture[str]
) -> None:
    server_cert, server_key, ca = _split(store, out, "localhost", capsys)
    client_cert, client_key, _ = _split(store, out, "alice", capsys)
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(server_cert, server_key)
    server_ctx.load_verify_locations(ca)
    server_ctx.verify_mode = ssl.CERT_REQUIRED
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.load_cert_chain(client_cert, client_key)
    client_ctx.load_verify_locations(ca)
    assert_that(asyncio.run(_exchange(server_ctx, client_ctx)), equal_to(b"hello alice\n"))


@pytest.mark.parametrize(
    ("flags", "message"),
    [
        (("--cert-out", "{out}/a.crt"), "--cert-out and --key-out together"),
        (("--key-out", "{out}/a.key"), "--cert-out and --key-out together"),
        (("--out", "{out}/a.pem", "--cert-out", "{out}/a.crt", "--key-out", "{out}/a.key"), "not both"),
        (("--out", "{out}/a.pem", "--key-out", "{out}/a.key"), "not both"),
        (("--cert-out", "{out}/a.pem", "--key-out", "{out}/a.pem"), "twice"),
        (("--cert-out", "{out}/a.crt", "--key-out", "{out}/a.key", "--ca-out", "{out}/../out/a.key"), "twice"),
        (("--out", "{out}/a.pem", "--ca-out", "{out}/a.pem"), "twice"),
        (("--cert-out", "{out}/a.crt", "--key-out", "{out}/missing/a.key"), "existing directory"),
        (("--cert-out", "{out}", "--key-out", "{out}/a.key"), "directory"),
    ],
)
def test_invalid_combinations_write_nothing(
    store: CertificateStore, out: Path, capsys: CaptureFixture[str], flags: tuple[str, ...], message: str
) -> None:
    words = [flag.format(out=out) for flag in flags]
    _, err = _run(store.root, "export", "pem", "alice", *words, capsys=capsys, expect_ok=False)
    assert_that(err, contains_string(message))
    assert_that(list(out.iterdir()), equal_to([]))


def test_a_symlink_destination_writes_nothing(
    store: CertificateStore, out: Path, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    target = tmp_path / "elsewhere"
    target.write_bytes(b"untouched")
    (out / "a.key").symlink_to(target)
    args = ("--cert-out", str(out / "a.crt"), "--key-out", str(out / "a.key"))
    _, err = _run(store.root, "export", "pem", "alice", *args, capsys=capsys, expect_ok=False)
    assert_that(err, contains_string("symlink"))
    assert_that(sorted(p.name for p in out.iterdir()), equal_to(["a.key"]))
    assert_that(target.read_bytes(), equal_to(b"untouched"))


def test_a_failed_write_leaves_existing_files_unchanged(
    store: CertificateStore, out: Path, capsys: CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("a.crt", "a.key"):
        (out / name).write_bytes(b"old " + name.encode())
    original = _fsutil._stage  # pyright: ignore[reportPrivateUsage]
    calls: list[Path] = []

    def flaky(path: Path, data: bytes, mode: int) -> Path:
        calls.append(path)
        if len(calls) == 2:
            raise OSError(28, "No space left on device")
        return original(path, data, mode)

    monkeypatch.setattr(_fsutil, "_stage", flaky)
    args = ("--cert-out", str(out / "a.crt"), "--key-out", str(out / "a.key"))
    _run(store.root, "export", "pem", "alice", *args, capsys=capsys, expect_ok=False)
    assert_that(sorted(p.name for p in out.iterdir()), equal_to(["a.crt", "a.key"]))
    assert_that((out / "a.crt").read_bytes(), equal_to(b"old a.crt"))
    assert_that((out / "a.key").read_bytes(), equal_to(b"old a.key"))


@pytest.mark.parametrize("existing", [True, False], ids=["replacing", "creating"])
def test_a_failed_rename_restores_the_files_already_renamed(
    store: CertificateStore,
    out: Path,
    capsys: CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    existing: bool,
) -> None:
    if existing:
        for name in ("a.crt", "a.key"):
            (out / name).write_bytes(b"old " + name.encode())
    original = os.replace
    renamed: list[str] = []

    def flaky(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
        if Path(dst).parent == out and Path(dst).name in ("a.crt", "a.key"):
            renamed.append(Path(dst).name)
            if len(renamed) == 2:
                raise PermissionError(1, "Operation not permitted")
        original(src, dst)

    monkeypatch.setattr(_fsutil.os, "replace", flaky)
    args = ("--cert-out", str(out / "a.crt"), "--key-out", str(out / "a.key"))
    _run(store.root, "export", "pem", "alice", *args, capsys=capsys, expect_ok=False)
    if existing:
        assert_that(sorted(p.name for p in out.iterdir()), equal_to(["a.crt", "a.key"]))
        assert_that((out / "a.crt").read_bytes(), equal_to(b"old a.crt"))
        assert_that((out / "a.key").read_bytes(), equal_to(b"old a.key"))
    else:
        assert_that(list(out.iterdir()), equal_to([]))


def test_a_backup_that_cannot_be_removed_does_not_fail_a_finished_write(
    out: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("a.crt", "a.key"):
        (out / name).write_bytes(b"old " + name.encode())
    original = Path.unlink

    def stuck(self: Path, missing_ok: bool = False) -> None:
        if self.name.endswith(".bak"):
            raise PermissionError(1, "Operation not permitted")
        original(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", stuck)
    _fsutil.write_files_atomic([(out / "a.crt", b"new crt", 0o644), (out / "a.key", b"new key", 0o600)])
    assert_that((out / "a.crt").read_bytes(), equal_to(b"new crt"))
    assert_that((out / "a.key").read_bytes(), equal_to(b"new key"))


def test_csr_signed_certificates_refuse_key_out(
    store: CertificateStore, out: Path, capsys: CaptureFixture[str]
) -> None:
    args = ("--cert-out", str(out / "l.crt"), "--key-out", str(out / "l.key"))
    _, err = _run(store.root, "export", "pem", "laptop", *args, capsys=capsys, expect_ok=False)
    assert_that(err, contains_string("its key stays on the device"))
    assert_that(list(out.iterdir()), equal_to([]))
    stdout, _ = _run(
        store.root,
        "export",
        "pem",
        "laptop",
        "--cert-out",
        str(out / "l.crt"),
        "--ca-out",
        str(out / "ca.crt"),
        capsys=capsys,
    )
    assert_that(stdout, contains_string("certificate only"))
    assert_that([_mode(out / "l.crt"), _mode(out / "ca.crt")], equal_to([0o644, 0o644]))


def test_combined_export_is_unchanged(store: CertificateStore, out: Path, capsys: CaptureFixture[str]) -> None:
    path = out / "alice.pem"
    stdout, _ = _run(store.root, "export", "pem", "alice", "--out", str(path), capsys=capsys)
    entry = store.get_certificate("alice")
    assert entry is not None
    assert_that(path.read_bytes(), equal_to(store.read_certificate_pem(entry) + store.read_key_pem(entry)))
    assert_that(_mode(path), equal_to(0o600))
    assert_that(stdout.strip(), equal_to(f"wrote {path}"))


def test_combined_export_with_ca_out(store: CertificateStore, out: Path, capsys: CaptureFixture[str]) -> None:
    args = ("--out", str(out / "alice.pem"), "--ca-out", str(out / "ca.crt"))
    _run(store.root, "export", "pem", "alice", *args, capsys=capsys)
    assert_that((out / "ca.crt").read_bytes(), equal_to(store.read_ca_certificate()))


def test_p12_refuses_the_split_flags(store: CertificateStore, out: Path, capsys: CaptureFixture[str]) -> None:
    _, err = _run(store.root, "export", "p12", "alice", "--ca-out", str(out / "ca.crt"), capsys=capsys, expect_ok=False)
    assert_that(err, contains_string("only supported for export pem"))
    assert_that(list(out.iterdir()), equal_to([]))


def test_ca_out_from_an_intermediate_store_includes_the_chain(
    tmp_path: Path, out: Path, capsys: CaptureFixture[str]
) -> None:
    root = CertificateStore(tmp_path / "root")
    root.write_ca(*generate_ca_certificate("Root", key_type="ec-p256", path_length=1))
    root.publish_crl()
    issuing = CertificateStore(tmp_path / "issuing")
    issuing.init_intermediate(root, "Issuing", key_type="ec-p256")
    issuing.issue_client("alice", key_type="ec-p256")
    cert, key, ca = _split(issuing, out, "alice", capsys)
    assert_that(ca.read_bytes(), equal_to((issuing.public_dir / "ca-chain.pem").read_bytes()))
    assert_that(len(x509.load_pem_x509_certificates(ca.read_bytes())), is_(2))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_cert_chain(cert, key)
    context.load_verify_locations(ca)
