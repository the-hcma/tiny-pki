"""Server certificates signed from a server's certificate signing request (issue #156)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import ipaddress
import json
import sys
import warnings
from collections.abc import Callable
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from hamcrest import assert_that, calling, contains_string, empty, equal_to, has_item, is_, is_not, raises
from pytest import CaptureFixture, MonkeyPatch

from tiny_pki import (
    TinyPkiError,
    TinyPkiWarning,
    generate_ca_certificate,
    generate_server_certificate,
    sign_server_csr,
)
from tiny_pki.cli.main import main
from tiny_pki.store import CertificateStore

type ServerKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey

_CA_CERT, _CA_KEY = generate_ca_certificate("CSR CA", key_type="ec-p256")
_CA_X509 = x509.load_pem_x509_certificate(_CA_CERT)
_HOME_CA_CERT, _HOME_CA_KEY = generate_ca_certificate("Home CA", key_type="ec-p256", permitted_subtrees=["home"])
_KEYS: dict[str, Callable[[], ServerKey]] = {
    "rsa-2048": lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
    "rsa-3072": lambda: rsa.generate_private_key(public_exponent=65537, key_size=3072),
    "ec-p256": lambda: ec.generate_private_key(ec.SECP256R1()),
}
_EC_KEY = ec.generate_private_key(ec.SECP256R1())


def _csr(
    key: ServerKey = _EC_KEY,
    *,
    common_name: str | None = "api.home",
    sans: list[str] | None = None,
    extensions: list[tuple[x509.ExtensionType, bool]] | None = None,
) -> bytes:
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)] if common_name else [])
    )
    if sans:
        names: list[x509.GeneralName] = []
        for san in sans:
            try:
                names.append(x509.IPAddress(ipaddress.ip_address(san)))
            except ValueError:
                names.append(x509.DNSName(san))
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    for extension, critical in extensions or []:
        builder = builder.add_extension(extension, critical=critical)
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


def _profile(cert: x509.Certificate) -> list[tuple[str, bool, object]]:
    """Extensions minus the key identifiers, which differ per key."""
    skip = (x509.SubjectKeyIdentifier, x509.AuthorityKeyIdentifier)
    return [(type(e.value).__name__, e.critical, e.value) for e in cert.extensions if not isinstance(e.value, skip)]


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


def _sans_of(cert: x509.Certificate) -> list[str]:
    value = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    return [str(name.value) for name in value]


def _sign(csr_pem: bytes, sans: list[str], **kwargs: object) -> tuple[x509.Certificate, list[str]]:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", TinyPkiWarning)
        cert_pem = sign_server_csr(_CA_CERT, _CA_KEY, csr_pem, "api.home", sans, **kwargs)  # type: ignore[arg-type]
    return x509.load_pem_x509_certificate(cert_pem), [str(w.message) for w in caught]


def _spki(key: ServerKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _spki_of(cert: x509.Certificate) -> bytes:
    return cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def test_accepted_csr_sans_are_normalized_and_added() -> None:
    cert, messages = _sign(_csr(sans=["API.home", "10.0.0.5", "api.home"]), ["api.home"], include_csr_sans=True)
    assert_that(_sans_of(cert), equal_to(["api.home", "10.0.0.5"]))
    assert_that(messages, is_(empty()))


def test_accepted_csr_sans_still_obey_the_name_constraints() -> None:
    csr_pem = _csr(sans=["api.home", "bank.example"])
    assert_that(
        calling(sign_server_csr).with_args(
            _HOME_CA_CERT, _HOME_CA_KEY, csr_pem, "api.home", ["api.home"], include_csr_sans=True
        ),
        raises(TinyPkiError, "permitted names"),
    )
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", TinyPkiWarning)
        cert_pem = sign_server_csr(_HOME_CA_CERT, _HOME_CA_KEY, csr_pem, "api.home", ["api.home"])
    assert_that(_sans_of(x509.load_pem_x509_certificate(cert_pem)), equal_to(["api.home"]))


def test_cli_asks_before_adding_csr_sans_at_a_terminal(
    tmp_path: Path, capsys: CaptureFixture[str], monkeypatch: MonkeyPatch
) -> None:
    store_path = tmp_path / "store"
    _run(store_path, "init", "--key-type", "ec-p256", capsys=capsys)
    csr_path = tmp_path / "api.csr"
    csr_path.write_bytes(_csr(sans=["api.home", "www.home"]))
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    prompts: list[str] = []
    answers = iter(["", "y"])

    def answer(prompt: str) -> str:
        prompts.append(prompt)
        return next(answers)

    monkeypatch.setattr("builtins.input", answer)

    for expected in (["api.home"], ["api.home", "www.home"]):
        _run(store_path, "sign", "server", "api.home", "--csr", str(csr_path), capsys=capsys)
        entry = CertificateStore(store_path).get_certificate("api.home")
        assert entry is not None
        cert = x509.load_pem_x509_certificate(CertificateStore(store_path).read_certificate_pem(entry))
        assert_that(_sans_of(cert), equal_to(expected))
    assert_that(prompts, equal_to(["The CSR also requests SANs www.home. Include them? [y/N] "] * 2))


def test_cli_sign_server_ignores_csr_sans_unless_accepted(
    tmp_path: Path, capsys: CaptureFixture[str], monkeypatch: MonkeyPatch
) -> None:
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    store_path = tmp_path / "store"
    _run(store_path, "init", "--key-type", "ec-p256", capsys=capsys)
    csr_path = tmp_path / "api.csr"
    csr_path.write_bytes(_csr(sans=["api.home", "www.home"]))
    cert_out = tmp_path / "api.crt"

    out, err = _run(
        store_path, "sign", "server", "api.home", "--csr", str(csr_path), "--out", str(cert_out), capsys=capsys
    )
    assert_that(out, contains_string("issued server api.home"))
    assert_that(out, contains_string("the private key stays on the server"))
    assert_that(err, contains_string("Ignored the SANs the CSR requests (www.home)"))
    cert = x509.load_pem_x509_certificate(cert_out.read_bytes())
    assert_that(_sans_of(cert), equal_to(["api.home"]))
    assert_that(_spki_of(cert), equal_to(_spki(_EC_KEY)))

    _run(store_path, "sign", "server", "api.home", "--csr", str(csr_path), "--accept-csr-sans", capsys=capsys)
    listed = json.loads(_run(store_path, "list", "servers", "--json", capsys=capsys)[0])
    active = [row for row in listed if row["status"] == "active"]
    assert_that([row["key_path"] for row in active], equal_to([""]))
    entry = CertificateStore(store_path).get_certificate("api.home")
    assert entry is not None
    renewed = x509.load_pem_x509_certificate(CertificateStore(store_path).read_certificate_pem(entry))
    assert_that(_sans_of(renewed), equal_to(["api.home", "www.home"]))

    pem_out = tmp_path / "export.pem"
    _run(store_path, "export", "pem", "api.home", "--out", str(pem_out), capsys=capsys)
    assert_that(pem_out.read_bytes(), equal_to(CertificateStore(store_path).read_certificate_pem(entry)))
    _, err = _run(store_path, "export", "p12", "api.home", capsys=capsys, expect_ok=False)
    assert_that(err, contains_string("its key stays on the server"))


def test_csr_sans_already_listed_sign_quietly() -> None:
    _, messages = _sign(_csr(sans=["api.home", "10.0.0.5"]), ["api.home", "10.0.0.5"])
    assert_that(messages, is_(empty()))


def test_csr_sans_are_ignored_unless_included() -> None:
    cert, messages = _sign(_csr(sans=["api.home", "www.home", "10.0.0.5"]), ["api.home"])
    assert_that(_sans_of(cert), equal_to(["api.home"]))
    assert_that(
        messages,
        equal_to(
            [
                "Ignored the SANs the CSR requests (www.home, 10.0.0.5); the certificate covers api.home. "
                "Include them explicitly or with include_csr_sans=True"
            ]
        ),
    )


@pytest.mark.parametrize("include_csr_sans", [False, True])
def test_csr_sans_of_other_types_are_ignored_with_a_warning(include_csr_sans: bool) -> None:
    requested = x509.SubjectAlternativeName(
        [
            x509.DNSName("api.home"),
            x509.UniformResourceIdentifier("https://api.home/"),
            x509.RFC822Name("ops@home.example"),
            x509.OtherName(x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"), b"\x0c\x03bob"),
        ]
    )
    cert, messages = _sign(_csr(extensions=[(requested, False)]), ["api.home"], include_csr_sans=include_csr_sans)
    assert_that(_sans_of(cert), equal_to(["api.home"]))
    assert_that(
        messages,
        equal_to(
            [
                "Ignored the CSR's requested SANs that are not DNS names or IP addresses (URI:https://api.home/, "
                "email:ops@home.example, otherName:1.3.6.1.4.1.311.20.2.3); "
                "server certificates carry only DNS and IP SANs"
            ]
        ),
    )


def test_server_csr_policy_matches_the_client_one() -> None:
    weak = _csr(rsa.generate_private_key(public_exponent=65537, key_size=1024))
    assert_that(
        calling(sign_server_csr).with_args(_CA_CERT, _CA_KEY, weak, "api.home", ["api.home"]),
        raises(TinyPkiError, "RSA key is 1024 bits"),
    )


@pytest.mark.parametrize("key_name", sorted(_KEYS))
def test_signed_certificate_matches_the_create_profile(key_name: str) -> None:
    key = _KEYS[key_name]()
    cert, _ = _sign(_csr(key), ["api.home", "10.0.0.5"])
    key_type = "ec-p256" if key_name == "ec-p256" else "rsa"
    key_size = None if key_type == "ec-p256" else int(key_name.split("-")[1])
    reference_pem, _ = generate_server_certificate(
        _CA_CERT, _CA_KEY, "api.home", ["api.home", "10.0.0.5"], key_type=key_type, key_size=key_size
    )
    reference = x509.load_pem_x509_certificate(reference_pem)

    cert.verify_directly_issued_by(_CA_X509)
    assert_that(_spki_of(cert), equal_to(_spki(key)))
    assert_that(cert.subject, equal_to(reference.subject))
    assert_that(_profile(cert), equal_to(_profile(reference)))
    validity = cert.not_valid_after_utc - cert.not_valid_before_utc
    assert_that(validity, equal_to(reference.not_valid_after_utc - reference.not_valid_before_utc))


def test_store_records_a_key_less_server_that_replaces_and_revokes_like_create(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "store")
    store.write_ca(_CA_CERT, _CA_KEY)
    store.publish_crl()
    previous = store.issue_server("api.home", ["api.home"], key_type="ec-p256")

    entry = store.sign_server_csr("api.home", _csr(), ["api.home"])

    assert_that(entry.key_path, equal_to(""))
    assert_that(entry.kind, equal_to("server"))
    live = sorted(p.name for p in store.servers_dir.iterdir())
    assert_that(live, equal_to([Path(entry.cert_path).name]))
    crl = x509.load_pem_x509_crl(store.read_crl() or b"")
    assert_that(crl.get_revoked_certificate_by_serial_number(int(previous.serial_number, 16)), is_not(None))
    assert_that(calling(store.read_key_pem).with_args(entry), raises(FileNotFoundError))
    store.revoke("api.home")
    store.delete(f"0x{entry.serial_number}")
    assert_that(store.get_certificate("api.home"), is_(None))


def test_store_server_signing_needs_the_secret_of_an_encrypted_ca(tmp_path: Path) -> None:
    secret = "s" * 32
    store = CertificateStore(tmp_path / "store")
    store.write_ca(_CA_CERT, _CA_KEY, key_secret=secret)
    store.publish_crl(key_secret=secret)
    assert_that(
        calling(store.sign_server_csr).with_args("api.home", _csr(), ["api.home"]),
        raises(TinyPkiError, "encrypted"),
    )
    assert_that(store.sign_server_csr("api.home", _csr(), ["api.home"], key_secret=secret).key_path, equal_to(""))


def test_the_ca_decides_name_and_extensions_whatever_the_csr_requests() -> None:
    csr_pem = _csr(
        common_name="root-ca",
        extensions=[
            (x509.BasicConstraints(ca=True, path_length=None), True),
            (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.CODE_SIGNING]), False),
        ],
    )
    cert, messages = _sign(csr_pem, ["api.home"])

    assert_that(cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, equal_to("api.home"))
    constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert_that(constraints, equal_to(x509.BasicConstraints(ca=False, path_length=None)))
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert_that(list(eku), equal_to([ExtendedKeyUsageOID.SERVER_AUTH]))
    assert_that(messages, has_item(contains_string("Ignored the CSR's common name 'root-ca'")))
    assert_that(
        messages,
        has_item(
            "Ignored the extensions the CSR requests (BasicConstraints, ExtendedKeyUsage); "
            "the CA sets the server profile"
        ),
    )


def test_the_cn_joins_the_sans_unless_declined() -> None:
    added, messages = _sign(_csr(), ["www.home"])
    assert_that(_sans_of(added), equal_to(["www.home", "api.home"]))
    assert_that(messages, has_item(contains_string("Added common_name 'api.home' to the SANs")))
    declined, _ = _sign(_csr(), ["www.home"], include_common_name_in_sans=False)
    assert_that(_sans_of(declined), equal_to(["www.home"]))


def test_validity_follows_the_server_caps() -> None:
    assert_that(
        calling(sign_server_csr).with_args(_CA_CERT, _CA_KEY, _csr(), "api.home", ["api.home"], validity_days=400),
        raises(TinyPkiError, "allow_long_validity"),
    )
    cert, _ = _sign(_csr(), ["api.home"], validity_days=400, allow_long_validity=True)
    assert_that((cert.not_valid_after_utc - cert.not_valid_before_utc).days, equal_to(400))
