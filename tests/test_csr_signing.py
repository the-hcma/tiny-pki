"""Client certificates signed from a device's certificate signing request (issue #154)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import hashlib
import json
import sys
import warnings
from collections.abc import Callable
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from hamcrest import assert_that, calling, contains_string, empty, equal_to, has_item, is_, is_not, raises
from pytest import CaptureFixture, MonkeyPatch

from tiny_pki import (
    TinyPkiError,
    TinyPkiWarning,
    generate_ca_certificate,
    generate_client_certificate,
    inspect_csr,
    sign_client_csr,
)
from tiny_pki.cli.main import main
from tiny_pki.store import CertificateStore

type DeviceKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey

_CA_CERT, _CA_KEY = generate_ca_certificate("CSR CA", key_type="ec-p256")
_CA_X509 = x509.load_pem_x509_certificate(_CA_CERT)
_SECRET = "s" * 32
_KEYS: dict[str, Callable[[], DeviceKey]] = {
    "rsa-2048": lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
    "rsa-3072": lambda: rsa.generate_private_key(public_exponent=65537, key_size=3072),
    "ec-p256": lambda: ec.generate_private_key(ec.SECP256R1()),
}
_EC_KEY = ec.generate_private_key(ec.SECP256R1())
# cryptography refuses to create SHA-1 signatures; this public CSR was made with
# `openssl req -new -sha1 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout /dev/null`.
_SHA1_CSR = Path(__file__).parent / "data" / "ecdsa-sha1.csr"


def _csr(
    key: DeviceKey = _EC_KEY,
    *,
    common_name: str | None = "alice-laptop",
    extensions: list[tuple[x509.ExtensionType, bool]] | None = None,
    algorithm: hashes.SHA224 | hashes.SHA256 | None = None,
    encoding: serialization.Encoding = serialization.Encoding.PEM,
) -> bytes:
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)] if common_name else [])
    )
    for extension, critical in extensions or []:
        builder = builder.add_extension(extension, critical=critical)
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return builder.sign(key, None).public_bytes(encoding)
    return builder.sign(key, algorithm or hashes.SHA256()).public_bytes(encoding)


def _sign(csr_pem: bytes, common_name: str = "alice-laptop", **kwargs: object) -> x509.Certificate:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", TinyPkiWarning)
        cert_pem = sign_client_csr(_CA_CERT, _CA_KEY, csr_pem, common_name, **kwargs)  # type: ignore[arg-type]
    return x509.load_pem_x509_certificate(cert_pem)


def _spki(key: DeviceKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _profile(cert: x509.Certificate) -> list[tuple[str, bool, object]]:
    """Extensions minus the key identifiers, which differ per key."""
    skip = (x509.SubjectKeyIdentifier, x509.AuthorityKeyIdentifier)
    return [(type(e.value).__name__, e.critical, e.value) for e in cert.extensions if not isinstance(e.value, skip)]


@pytest.mark.parametrize("key_name", sorted(_KEYS))
def test_signed_certificate_matches_the_create_profile(key_name: str) -> None:
    key = _KEYS[key_name]()
    cert = _sign(_csr(key))
    key_type = "ec-p256" if key_name == "ec-p256" else "rsa"
    key_size = None if key_type == "ec-p256" else int(key_name.split("-")[1])
    reference_pem, _ = generate_client_certificate(
        _CA_CERT, _CA_KEY, "alice-laptop", key_type=key_type, key_size=key_size
    )
    reference = x509.load_pem_x509_certificate(reference_pem)

    cert.verify_directly_issued_by(_CA_X509)
    assert_that(_spki_of(cert), equal_to(_spki(key)))
    assert_that(cert.subject, equal_to(reference.subject))
    assert_that(_profile(cert), equal_to(_profile(reference)))
    ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    assert_that(ski, equal_to(x509.SubjectKeyIdentifier.from_public_key(key.public_key())))


def test_the_ca_decides_name_and_extensions_whatever_the_csr_requests() -> None:
    csr_pem = _csr(
        common_name="root-ca",
        extensions=[
            (x509.BasicConstraints(ca=True, path_length=None), True),
            (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CODE_SIGNING]), False),
            (x509.SubjectAlternativeName([x509.DNSName("bank.example")]), False),
        ],
    )
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", TinyPkiWarning)
        cert = x509.load_pem_x509_certificate(sign_client_csr(_CA_CERT, _CA_KEY, csr_pem, "alice-laptop"))

    assert_that(cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, equal_to("alice-laptop"))
    constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert_that(constraints, equal_to(x509.BasicConstraints(ca=False, path_length=None)))
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert_that(list(eku), equal_to([ExtendedKeyUsageOID.CLIENT_AUTH]))
    assert_that(
        calling(cert.extensions.get_extension_for_class).with_args(x509.SubjectAlternativeName),
        raises(x509.ExtensionNotFound),
    )
    messages = [str(w.message) for w in caught]
    assert_that(messages, has_item(contains_string("Ignored the CSR's common name 'root-ca'")))
    assert_that(
        messages,
        has_item(contains_string("BasicConstraints, ExtendedKeyUsage, SubjectAlternativeName")),
    )


def test_a_csr_naming_the_same_cn_without_extensions_signs_quietly() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", TinyPkiWarning)
        sign_client_csr(_CA_CERT, _CA_KEY, _csr(), "alice-laptop")
    assert_that(caught, is_(empty()))


def test_der_and_windows_certreq_headers_are_accepted() -> None:
    der = _csr(encoding=serialization.Encoding.DER)
    certreq = _csr().replace(b"CERTIFICATE REQUEST", b"NEW CERTIFICATE REQUEST")
    for data in (der, certreq):
        assert_that(_spki_of(_sign(data)), equal_to(_spki(_EC_KEY)))


def _tampered_signature() -> bytes:
    der = bytearray(_csr(encoding=serialization.Encoding.DER))
    der[-1] ^= 0x01
    return bytes(der)


@pytest.mark.parametrize(
    ("make_csr", "message"),
    [
        (_tampered_signature, "signature does not verify"),
        (lambda: _SHA1_CSR.read_bytes(), "signed with sha1"),
        (lambda: _csr(algorithm=hashes.SHA224()), "signed with sha224"),
        (lambda: _csr(rsa.generate_private_key(public_exponent=65537, key_size=1024)), "RSA key is 1024 bits"),
        (lambda: _csr(rsa.generate_private_key(public_exponent=3, key_size=2048)), "RSA public exponent is 3"),
        (lambda: _csr(ec.generate_private_key(ec.SECP384R1())), "EC key is on secp384r1"),
        (lambda: _csr(ed25519.Ed25519PrivateKey.generate()), "Ed25519PublicKey key is not supported"),
    ],
    ids=["bad-signature", "sha1", "sha224", "rsa-1024", "rsa-e3", "p384", "ed25519"],
)
def test_csrs_outside_the_policy_are_refused(make_csr: Callable[[], bytes], message: str) -> None:
    csr_pem = make_csr()
    assert_that(calling(_sign).with_args(csr_pem), raises(TinyPkiError, message))
    assert_that(inspect_csr(csr_pem).problems, has_item(contains_string(message)))


@pytest.mark.parametrize("data", [b"", b"not a csr", _CA_CERT], ids=["empty", "garbage", "certificate"])
def test_input_that_is_not_a_csr_is_refused(data: bytes) -> None:
    assert_that(
        calling(sign_client_csr).with_args(_CA_CERT, _CA_KEY, data, "alice-laptop"),
        raises(TinyPkiError, "certificate signing request"),
    )


def test_name_and_validity_policy_match_create() -> None:
    permitted_cert, permitted_key = generate_ca_certificate("Home CA", key_type="ec-p256", permitted_subtrees=["home"])
    csr_pem = _csr()
    assert_that(
        calling(sign_client_csr).with_args(permitted_cert, permitted_key, csr_pem, "alice.example.com"),
        raises(TinyPkiError, "permitted names"),
    )
    sign_client_csr(permitted_cert, permitted_key, _csr(common_name="alice.home"), "alice.home")
    assert_that(calling(_sign).with_args(csr_pem, "bob,CN=alice"), raises(TinyPkiError, "DN special character"))
    assert_that(calling(_sign).with_args(csr_pem, validity_days=900), raises(TinyPkiError, "validity_days <= 825"))
    long_lived = _sign(csr_pem, validity_days=900, allow_long_validity=True)
    assert_that((long_lived.not_valid_after_utc - long_lived.not_valid_before_utc).days, equal_to(900))


def test_inspect_reports_the_request_and_the_fingerprint_to_compare() -> None:
    key = _KEYS["rsa-3072"]()
    csr_pem = _csr(key, extensions=[(x509.SubjectAlternativeName([x509.DNSName("laptop.home")]), False)])
    summary = inspect_csr(csr_pem)
    expected = ":".join(f"{b:02X}" for b in hashlib.sha256(_spki(key)).digest())
    assert_that(summary.public_key_fingerprint, equal_to(expected))
    assert_that(summary.common_name, equal_to("alice-laptop"))
    assert_that(summary.sans, equal_to(("laptop.home",)))
    assert_that((summary.key_type, summary.key_size), equal_to(("rsa", 3072)))
    assert_that(summary.signature_hash, equal_to("sha256"))
    assert_that(summary.requested_extensions, equal_to(("SubjectAlternativeName",)))
    assert_that(summary.problems, is_(empty()))


def test_store_records_a_key_less_entry_that_replaces_and_revokes_like_create(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "store")
    store.write_ca(_CA_CERT, _CA_KEY)
    store.publish_crl()
    previous = store.issue_client("alice-laptop", key_type="ec-p256")

    entry = store.sign_client_csr("alice-laptop", _csr())

    assert_that(entry.key_path, equal_to(""))
    assert_that(sorted(p.name for p in store.clients_dir.iterdir()), equal_to([Path(entry.cert_path).name]))
    assert_that(_spki_of(x509.load_pem_x509_certificate(store.read_certificate_pem(entry))), equal_to(_spki(_EC_KEY)))
    revoked = {serial for serial, _ in store.revoked_entries()}
    assert_that(revoked, equal_to({int(previous.serial_number, 16)}))
    crl = x509.load_pem_x509_crl(store.read_crl() or b"")
    assert_that(crl.get_revoked_certificate_by_serial_number(int(previous.serial_number, 16)), is_not(None))
    assert_that(calling(store.read_key_pem).with_args(entry), raises(FileNotFoundError))

    rotated = store.sign_client_csr("alice-laptop", _csr(ec.generate_private_key(ec.SECP256R1())), keep_previous=True)
    assert_that(store.superseded_serials(), equal_to({entry.serial_number: rotated.serial_number}))
    store.revoke(f"0x{entry.serial_number}")
    store.delete(f"0x{entry.serial_number}")
    assert_that(store.get_certificate("alice-laptop"), equal_to(rotated))


def test_store_signing_needs_the_secret_of_an_encrypted_ca(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "store")
    store.write_ca(_CA_CERT, _CA_KEY, key_secret=_SECRET)
    store.publish_crl(key_secret=_SECRET)
    assert_that(calling(store.sign_client_csr).with_args("alice-laptop", _csr()), raises(TinyPkiError, "encrypted"))
    assert_that(store.list_certificates(), is_(empty()))
    entry = store.sign_client_csr("alice-laptop", _csr(), key_secret=_SECRET)
    assert_that(entry.key_path, equal_to(""))


def _run(store: Path, *words: str, capsys: CaptureFixture[str], expect_ok: bool = True) -> tuple[str, str]:
    argv = ["--store", str(store), "--color", "never", *words]
    if expect_ok:
        main(argv)
    else:
        with pytest.raises(SystemExit) as exited:
            main(argv)
        assert_that(exited.value.code, equal_to(1))
    captured = capsys.readouterr()
    return captured.out, captured.err


def test_cli_sign_inspect_and_export(tmp_path: Path, capsys: CaptureFixture[str], monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    store_path = tmp_path / "store"
    _run(store_path, "init", "--key-type", "ec-p256", capsys=capsys)
    csr_path = tmp_path / "laptop.csr"
    csr_path.write_bytes(_csr(common_name="laptop"))

    out, _ = _run(store_path, "inspect", str(csr_path), capsys=capsys)
    fingerprint = ":".join(f"{b:02X}" for b in hashlib.sha256(_spki(_EC_KEY)).digest())
    assert_that(out, contains_string(f"public key sha256 {fingerprint}"))
    assert_that(out, contains_string("signable"))

    cert_out = tmp_path / "alice-laptop.crt"
    out, err = _run(
        store_path, "sign", "client", "alice-laptop", "--csr", str(csr_path), "--out", str(cert_out), capsys=capsys
    )
    assert_that(out, contains_string("issued client alice-laptop"))
    assert_that(err, contains_string("Ignored the CSR's common name 'laptop'"))
    cert = x509.load_pem_x509_certificate(cert_out.read_bytes())
    assert_that(_spki_of(cert), equal_to(_spki(_EC_KEY)))

    listed = json.loads(_run(store_path, "list", "clients", "--json", capsys=capsys)[0])
    assert_that([row["key_path"] for row in listed], equal_to([""]))

    pem_out = tmp_path / "export.pem"
    _run(store_path, "export", "pem", "alice-laptop", "--out", str(pem_out), capsys=capsys)
    assert_that(pem_out.read_bytes(), equal_to(cert_out.read_bytes()))
    _, err = _run(store_path, "export", "p12", "alice-laptop", capsys=capsys, expect_ok=False)
    assert_that(err, contains_string("its key stays on the device"))

    _run(store_path, "revoke", "alice-laptop", capsys=capsys)
    out, _ = _run(store_path, "show", "crl", capsys=capsys)
    assert_that(out, contains_string(format(cert.serial_number, "x")))


def test_cli_refuses_bad_sign_invocations(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    store_path = tmp_path / "store"
    _run(store_path, "init", "--key-type", "ec-p256", capsys=capsys)
    weak_path = tmp_path / "weak.csr"
    weak_path.write_bytes(_csr(rsa.generate_private_key(public_exponent=65537, key_size=1024)))

    out, _ = _run(store_path, "inspect", str(weak_path), capsys=capsys)
    assert_that(out, contains_string("refused"))
    assert_that(out, contains_string("RSA key is 1024 bits"))
    good_path = tmp_path / "good.csr"
    good_path.write_bytes(_csr())
    cases = [
        (("sign", "client", "alice", "--csr", str(weak_path)), "RSA key is 1024 bits"),
        (("sign", "server", "api.home", "--csr", str(weak_path)), "RSA key is 1024 bits"),
        (("sign", "client", "alice"), "Expected --csr PATH"),
        (("sign", "ca", "alice", "--csr", str(good_path)), "Expected sign client|server"),
        (("sign", "client", "alice", "--csr", str(good_path), "--san", "a.home"), "only supported for server"),
        (("sign", "client", "alice", "--csr", str(good_path), "--accept-csr-sans"), "only supported for server"),
        (("sign", "server", "api.home", "--csr", str(good_path), "--keep-previous"), "only supported for client"),
        (("sign", "server", "api.home", "--csr", str(good_path), "--no-cn-san"), "Expected --san with --no-cn-san"),
        (("sign", "client", "alice", "--csr", str(tmp_path / "missing.csr")), "readable --csr file"),
    ]
    for words, message in cases:
        _, err = _run(store_path, *words, capsys=capsys, expect_ok=False)
        assert_that(err, contains_string(message))
    assert_that(CertificateStore(store_path).list_certificates(), is_(empty()))


def test_cli_help_describes_sign(capsys: CaptureFixture[str]) -> None:
    main(["--color", "never", "help", "sign"])
    out = capsys.readouterr().out
    assert_that(out, contains_string("usage: sign client|server NAME --csr PATH"))
    assert_that(out, contains_string("--csr PATH"))


def _spki_of(cert: x509.Certificate) -> bytes:
    return cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
