"""URI SANs on client certificates and URI Name Constraints (issue #168)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from hamcrest import assert_that, calling, contains_string, equal_to, has_entries, is_, none, not_, raises
from pytest import CaptureFixture

from tiny_pki import (
    TinyPkiError,
    generate_ca_certificate,
    generate_client_certificate,
    generate_intermediate_ca_certificate,
    get_certificate_sans,
    get_certificate_uris,
    sign_client_csr,
)
from tiny_pki._keys import load_private_key
from tiny_pki.cli.main import main
from tiny_pki.names import normalize_uri_san
from tiny_pki.store import CertificateStore

_SPIFFE = "spiffe://example.home/device/sensor-1"
_CA = generate_ca_certificate("URI CA", key_type="ec-p256")
_CONSTRAINED = generate_ca_certificate(
    "Constrained CA", key_type="ec-p256", permitted_subtrees=["home", "uri:example.home", "uri:.svc.home"]
)


def _run(store: Path, *words: str, capsys: CaptureFixture[str], expect_ok: bool = True) -> tuple[str, str]:
    argv = ["--store", str(store), "--color", "never", *words]
    if expect_ok:
        main(argv)
    else:
        with pytest.raises(SystemExit):
            main(argv)
    captured = capsys.readouterr()
    return captured.out, captured.err


def _csr(*, uri: str | None = None) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "device")])
    )
    if uri is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri)]), False)
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


@pytest.mark.parametrize(
    ("uri", "expected"),
    [
        (_SPIFFE, _SPIFFE),
        ("  SPIFFE://example.home/device/a_b-c.1  ", "spiffe://example.home/device/a_b-c.1"),
        ("https://Broker.Home:8443/clients/alice", "https://Broker.Home:8443/clients/alice"),
        ("urn-like+x.y://host/", "urn-like+x.y://host/"),
    ],
)
def test_normalize_uri_san_accepts_and_lower_cases_the_scheme(uri: str, expected: str) -> None:
    assert_that(normalize_uri_san(uri), equal_to(expected))


@pytest.mark.parametrize(
    "uri",
    [
        "",
        "sensor-1",
        "/device/sensor-1",
        "mailto:alice@example.home",
        "https://alice@example.home/x",
        "https://example.home/x?id=1",
        "https://example.home/x#frag",
        "https://exämple.home/x",
        "https://example.home/a b",
        "https://example.home/\x00",
        "1http://example.home/",
        "https://[::1/",
        "https://example.home/" + "a" * 2048,
    ],
)
def test_normalize_uri_san_rejects_malformed_uris(uri: str) -> None:
    assert_that(calling(normalize_uri_san).with_args(uri), raises(TinyPkiError, "absolute URI"))


@pytest.mark.parametrize(
    "uri",
    [
        "spiffe://Example.home/device/x",
        "spiffe://example.home:8443/device/x",
        "spiffe://example.home",
        "spiffe://example.home/",
        "spiffe://example.home/device//x",
        "spiffe://example.home/device/x/",
        "spiffe://example.home/device/../x",
        "spiffe://example.home/./x",
        "spiffe://example.home/device/x%20y",
        "spiffe://exa+mple.home/x",
    ],
)
def test_normalize_uri_san_enforces_spiffe_rules(uri: str) -> None:
    assert_that(calling(normalize_uri_san).with_args(uri), raises(TinyPkiError, "SPIFFE ID"))


def test_client_certificate_carries_exactly_the_uri_san() -> None:
    cert_pem, _ = generate_client_certificate(*_CA, "sensor-1", uri_san="SPIFFE://example.home/device/sensor-1")
    cert = x509.load_pem_x509_certificate(cert_pem)
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert_that(san.critical, is_(False))
    assert_that(list(san.value), equal_to([x509.UniformResourceIdentifier(_SPIFFE)]))
    assert_that(get_certificate_uris(cert_pem), equal_to([_SPIFFE]))
    assert_that(get_certificate_sans(cert_pem), equal_to([]))


def test_client_certificate_without_uri_has_no_san() -> None:
    cert = x509.load_pem_x509_certificate(generate_client_certificate(*_CA, "plain")[0])
    assert_that(
        calling(cert.extensions.get_extension_for_class).with_args(x509.SubjectAlternativeName),
        raises(x509.ExtensionNotFound),
    )


def test_client_certificate_rejects_an_invalid_uri() -> None:
    assert_that(
        calling(generate_client_certificate).with_args(*_CA, "x", uri_san="spiffe://example.home/../x"),
        raises(TinyPkiError, "SPIFFE ID"),
    )


def test_sign_client_csr_uses_the_given_uri_and_ignores_the_csr_sans() -> None:
    with pytest.warns(UserWarning):
        cert_pem = sign_client_csr(*_CA, _csr(uri="spiffe://evil.home/device/root"), "sensor-1", uri_san=_SPIFFE)
    assert_that(get_certificate_uris(cert_pem), equal_to([_SPIFFE]))


def test_sign_client_csr_without_uri_drops_the_csr_uri() -> None:
    with pytest.warns(UserWarning):
        cert_pem = sign_client_csr(*_CA, _csr(uri=_SPIFFE), "sensor-1")
    assert_that(get_certificate_uris(cert_pem), equal_to([]))


def test_uri_subtrees_become_uri_name_constraints() -> None:
    cert = x509.load_pem_x509_certificate(_CONSTRAINED[0])
    constraints = cert.extensions.get_extension_for_class(x509.NameConstraints).value
    assert_that(
        list(constraints.permitted_subtrees or []),
        equal_to(
            [
                x509.DNSName("home"),
                x509.UniformResourceIdentifier("example.home"),
                x509.UniformResourceIdentifier(".svc.home"),
            ]
        ),
    )


@pytest.mark.parametrize("entry", ["uri:", "uri:https://example.home", "uri:*.home", "uri:example.home/x", "uri:a..b"])
def test_invalid_uri_subtrees_are_rejected(entry: str) -> None:
    assert_that(
        calling(generate_ca_certificate).with_args(key_type="ec-p256", permitted_subtrees=[entry]),
        raises(TinyPkiError),
    )


@pytest.mark.parametrize(
    "uri", ["spiffe://example.home/device/a", "https://EXAMPLE.home/x", "spiffe://mqtt.svc.home/device/b"]
)
def test_constrained_ca_issues_uris_within_its_subtrees(uri: str) -> None:
    cert_pem, _ = generate_client_certificate(*_CONSTRAINED, "device", uri_san=uri)
    assert_that(get_certificate_uris(cert_pem), equal_to([uri]))


@pytest.mark.parametrize(
    "uri", ["spiffe://sub.example.home/device/a", "spiffe://svc.home/device/a", "spiffe://other.home/device/a"]
)
def test_constrained_ca_refuses_uris_outside_its_subtrees(uri: str) -> None:
    assert_that(
        calling(generate_client_certificate).with_args(*_CONSTRAINED, "device", uri_san=uri),
        raises(TinyPkiError, "permitted URI hosts"),
    )


def test_a_ca_without_a_uri_subtree_refuses_uri_sans() -> None:
    dns_only = generate_ca_certificate("DNS CA", key_type="ec-p256", permitted_subtrees=["home"])
    assert_that(
        calling(generate_client_certificate).with_args(*dns_only, "device", uri_san=_SPIFFE),
        raises(TinyPkiError, "URI"),
    )


def test_intermediate_narrows_uri_subtrees_within_the_issuer() -> None:
    root = generate_ca_certificate(
        "Root", key_type="ec-p256", path_length=1, permitted_subtrees=["home", "uri:.svc.home"]
    )
    narrowed = generate_intermediate_ca_certificate(
        *root, "Issuing", key_type="ec-p256", permitted_subtrees=["uri:mqtt.svc.home"]
    )
    cert_pem, _ = generate_client_certificate(*narrowed, "device", uri_san="spiffe://mqtt.svc.home/device/a")
    assert_that(get_certificate_uris(cert_pem), equal_to(["spiffe://mqtt.svc.home/device/a"]))
    assert_that(
        calling(generate_intermediate_ca_certificate).with_args(
            *root, "Wider", key_type="ec-p256", permitted_subtrees=["uri:example.home"]
        ),
        raises(TinyPkiError),
    )


def _forged_leaf(ca: tuple[bytes, bytes], uri: str) -> bytes:
    ca_cert = x509.load_pem_x509_certificate(ca[0])
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "device")]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri)]), critical=False)
        .sign(load_private_key(ca[1]), hashes.SHA256())  # type: ignore[arg-type]
        .public_bytes(serialization.Encoding.PEM)
    )


def _openssl_verify(tmp_path: Path, ca_pem: bytes, leaf_pem: bytes) -> subprocess.CompletedProcess[str]:
    (tmp_path / "ca.pem").write_bytes(ca_pem)
    (tmp_path / "leaf.pem").write_bytes(leaf_pem)
    return subprocess.run(
        ["openssl", "verify", "-CAfile", "ca.pem", "leaf.pem"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not installed")
def test_openssl_agrees_with_the_uri_constraint_semantics(tmp_path: Path) -> None:
    issued, _ = generate_client_certificate(*_CONSTRAINED, "device", uri_san="spiffe://mqtt.svc.home/device/a")
    assert_that(_openssl_verify(tmp_path, _CONSTRAINED[0], issued).returncode, equal_to(0))
    for outside in ("spiffe://sub.example.home/device/a", "spiffe://svc.home/device/a"):
        result = _openssl_verify(tmp_path, _CONSTRAINED[0], _forged_leaf(_CONSTRAINED, outside))
        assert_that(result.returncode, not_(equal_to(0)))
        assert_that(result.stdout + result.stderr, contains_string("subtree violation"))


def test_store_records_the_uri_in_the_index(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "store")
    store.write_ca(*_CA)
    store.publish_crl()
    entry = store.issue_client("sensor-1", uri_san=_SPIFFE)
    plain = store.issue_client("plain")
    assert_that(entry.uri_san, equal_to(_SPIFFE))
    assert_that(plain.uri_san, is_(none()))
    rows = {row["common_name"]: row for row in json.loads(store.index_path.read_text())}
    assert_that(rows["sensor-1"], has_entries(uri_san=_SPIFFE))
    assert_that(rows["plain"], not_(has_entries(uri_san=None)))
    assert_that("uri_san" in rows["plain"], is_(False))
    reopened = CertificateStore(store.root).get_certificate("sensor-1")
    assert reopened is not None
    assert_that(reopened.uri_san, equal_to(_SPIFFE))


def test_store_keeps_the_uri_across_rotation_and_revocation(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "store")
    store.write_ca(*_CA)
    store.publish_crl()
    old = store.issue_client("sensor-1", uri_san=_SPIFFE)
    store.issue_client("sensor-1", uri_san="spiffe://example.home/device/sensor-1b", keep_previous=True)
    by_serial = {e.serial_number: e for e in store.list_certificates(status="all")}
    assert_that(by_serial[old.serial_number].uri_san, equal_to(_SPIFFE))
    store.revoke(f"0x{old.serial_number}")
    revoked = {e.serial_number: e for e in store.list_certificates(status="revoked")}
    assert_that(revoked[old.serial_number].uri_san, equal_to(_SPIFFE))


def test_store_sign_client_csr_records_the_uri(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "store")
    store.write_ca(*_CA)
    store.publish_crl()
    with pytest.warns(UserWarning):
        entry = store.sign_client_csr("sensor-1", _csr(), uri_san=_SPIFFE)
    assert_that(entry.uri_san, equal_to(_SPIFFE))


def test_cli_issues_lists_and_inspects_the_uri(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    root = tmp_path / "store"
    _run(root, "init", "--key-type", "ec-p256", "--permit", "home", "--permit-uri", "example.home", capsys=capsys)
    _run(root, "create", "client", "sensor-1", "--key-type", "ec-p256", "--uri-san", _SPIFFE, capsys=capsys)
    out, _ = _run(root, "list", "clients", capsys=capsys)
    assert_that(out, contains_string(f"uri={_SPIFFE}"))
    out, _ = _run(root, "list", "clients", "--json", capsys=capsys)
    assert_that(json.loads(out)[0], has_entries(uri_san=_SPIFFE))
    out, _ = _run(root, "inspect", "sensor-1", capsys=capsys)
    assert_that(out, contains_string(f"uris      {_SPIFFE}"))
    _, err = _run(
        root, "create", "client", "x", "--uri-san", "spiffe://other.home/device/x", capsys=capsys, expect_ok=False
    )
    assert_that(err, contains_string("permitted URI hosts"))


def test_cli_signs_a_csr_with_a_uri(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    root = tmp_path / "store"
    _run(root, "init", "--key-type", "ec-p256", capsys=capsys)
    csr_path = tmp_path / "device.csr"
    csr_path.write_bytes(_csr())
    _run(root, "sign", "client", "sensor-1", "--csr", str(csr_path), "--uri-san", _SPIFFE, capsys=capsys)
    entry = CertificateStore(root).get_certificate("sensor-1")
    assert entry is not None
    assert_that(entry.uri_san, equal_to(_SPIFFE))


@pytest.mark.parametrize(
    ("words", "message"),
    [
        (("create", "server", "api.home", "--uri-san", _SPIFFE), "--uri-san are only supported for client"),
        (("sign", "server", "api.home", "--csr", "x.csr", "--uri-san", _SPIFFE), "--uri-san is only supported"),
        (("sign", "client", "x", "--csr", "x.csr", "--permit-uri", "example.home"), "only supported for intermediate"),
    ],
)
def test_cli_rejects_misplaced_uri_flags(
    tmp_path: Path, capsys: CaptureFixture[str], words: tuple[str, ...], message: str
) -> None:
    root = tmp_path / "store"
    _run(root, "init", "--key-type", "ec-p256", capsys=capsys)
    _, err = _run(root, *words, capsys=capsys, expect_ok=False)
    assert_that(err, contains_string(message))
