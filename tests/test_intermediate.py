"""Root CAs with path_length=1 sign intermediate CAs, which sign leaves (issue #161)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import shutil
import subprocess
import warnings
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from hamcrest import assert_that, calling, contains_string, equal_to, has_length, is_, raises

from tiny_pki import (
    DEFAULT_INTERMEDIATE_VALIDITY_DAYS,
    TinyPkiError,
    TinyPkiWarning,
    generate_ca_certificate,
    generate_intermediate_ca_certificate,
    generate_pkcs12,
    generate_server_certificate,
    sign_intermediate_csr,
)

_ROOT = generate_ca_certificate("Root CA", key_type="ec-p256", path_length=1, permitted_subtrees=["home.arpa"])


def _basic_constraints(cert_pem: bytes) -> x509.Extension[x509.BasicConstraints]:
    cert = x509.load_pem_x509_certificate(cert_pem)
    return cert.extensions.get_extension_for_class(x509.BasicConstraints)


def _csr(common_name: str, *, with_ca_extension: bool = False) -> tuple[bytes, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    )
    if with_ca_extension:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM), key


def _permitted(cert_pem: bytes) -> list[str]:
    cert = x509.load_pem_x509_certificate(cert_pem)
    constraints = cert.extensions.get_extension_for_class(x509.NameConstraints).value
    return [str(name.value) for name in constraints.permitted_subtrees or []]


def test_root_path_length_defaults_to_zero_and_accepts_one() -> None:
    default_cert, _ = generate_ca_certificate("Leaf-only CA", key_type="ec-p256")
    assert_that(_basic_constraints(default_cert).value.path_length, equal_to(0))
    assert_that(_basic_constraints(_ROOT[0]).value.path_length, equal_to(1))


@pytest.mark.parametrize("path_length", [2, -1, True])
def test_root_path_length_rejects_other_values(path_length: int) -> None:
    assert_that(
        calling(generate_ca_certificate).with_args("Root", key_type="ec-p256", path_length=path_length),
        raises(TinyPkiError, "Expected path_length 0"),
    )


def test_intermediate_profile_chains_to_the_root() -> None:
    cert_pem, key_pem = generate_intermediate_ca_certificate(*_ROOT, "Issuing CA", key_type="ec-p256")
    cert = x509.load_pem_x509_certificate(cert_pem)
    root = x509.load_pem_x509_certificate(_ROOT[0])
    cert.verify_directly_issued_by(root)
    constraints = _basic_constraints(cert_pem)
    assert_that(constraints.critical, is_(True))
    assert_that((constraints.value.ca, constraints.value.path_length), equal_to((True, 0)))
    usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
    assert_that(usage.critical, is_(True))
    assert_that((usage.value.key_cert_sign, usage.value.crl_sign), equal_to((True, True)))
    aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    root_ski = root.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    assert_that(aki.key_identifier, equal_to(root_ski.digest))
    assert_that(cert.issuer, equal_to(root.subject))
    assert_that(cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value, equal_to("tiny-pki"))
    lifetime = cert.not_valid_after_utc - cert.not_valid_before_utc
    assert_that(lifetime.days, equal_to(DEFAULT_INTERMEDIATE_VALIDITY_DAYS))
    leaf_pem, _ = generate_server_certificate(cert_pem, key_pem, "nas.home.arpa", ["nas.home.arpa"])
    x509.load_pem_x509_certificate(leaf_pem).verify_directly_issued_by(cert)


def test_intermediate_inherits_and_narrows_name_constraints() -> None:
    inherited, _ = generate_intermediate_ca_certificate(*_ROOT, "Issuing CA", key_type="ec-p256")
    assert_that(_permitted(inherited), equal_to(["home.arpa"]))
    narrowed, key = generate_intermediate_ca_certificate(
        *_ROOT, "Lab CA", key_type="ec-p256", permitted_subtrees=["lab.home.arpa"]
    )
    assert_that(_permitted(narrowed), equal_to(["lab.home.arpa"]))
    assert_that(
        calling(generate_server_certificate).with_args(narrowed, key, "nas.home.arpa", ["nas.home.arpa"]),
        raises(TinyPkiError, "permitted names"),
    )


def test_intermediate_refuses_subtrees_outside_the_issuer() -> None:
    assert_that(
        calling(generate_intermediate_ca_certificate).with_args(
            *_ROOT, "Wide CA", key_type="ec-p256", permitted_subtrees=["example.com"]
        ),
        raises(TinyPkiError, "within the issuer's permitted names"),
    )


def test_unconstrained_root_gives_an_unconstrained_intermediate() -> None:
    root = generate_ca_certificate("Open Root", key_type="ec-p256", path_length=1)
    cert_pem, _ = generate_intermediate_ca_certificate(*root, "Open Issuing", key_type="ec-p256")
    cert = x509.load_pem_x509_certificate(cert_pem)
    assert_that(
        calling(cert.extensions.get_extension_for_class).with_args(x509.NameConstraints),
        raises(x509.ExtensionNotFound),
    )


def test_intermediate_refuses_a_leaf_only_issuer() -> None:
    leaf_only = generate_ca_certificate("Leaf-only CA", key_type="ec-p256")
    assert_that(
        calling(generate_intermediate_ca_certificate).with_args(*leaf_only, "Issuing CA", key_type="ec-p256"),
        raises(TinyPkiError, r"path_length=1 \(CLI: init --path-length 1\)"),
    )
    intermediate = generate_intermediate_ca_certificate(*_ROOT, "Issuing CA", key_type="ec-p256")
    assert_that(
        calling(generate_intermediate_ca_certificate).with_args(*intermediate, "Nested CA", key_type="ec-p256"),
        raises(TinyPkiError, "signs only leaves"),
    )


def test_intermediate_refuses_a_non_ca_issuer() -> None:
    root = generate_ca_certificate("Open Root", key_type="ec-p256", path_length=1)
    leaf = generate_server_certificate(*root, "host.example", ["host.example"], key_type="ec-p256")
    assert_that(
        calling(generate_intermediate_ca_certificate).with_args(*leaf, "Issuing CA", key_type="ec-p256"),
        raises(TinyPkiError, "Expected a CA certificate as the issuer"),
    )


def test_intermediate_refuses_an_issuer_without_key_cert_sign() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "No keyCertSign CA")])
    now = datetime.now(UTC)
    usage = x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(usage, critical=True)
        .sign(key, hashes.SHA256())
    )
    issuer = (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
    )
    assert_that(
        calling(generate_intermediate_ca_certificate).with_args(*issuer, "Issuing CA", key_type="ec-p256"),
        raises(TinyPkiError, "Key Usage allows keyCertSign"),
    )
    assert_that(
        calling(sign_intermediate_csr).with_args(*issuer, _csr("x")[0], "Issuing CA"),
        raises(TinyPkiError, "Key Usage allows keyCertSign"),
    )


def test_intermediate_may_not_outlive_its_issuer() -> None:
    root = generate_ca_certificate("Short Root", key_type="ec-p256", path_length=1, validity_days=365)
    assert_that(
        calling(generate_intermediate_ca_certificate).with_args(*root, "Issuing CA", key_type="ec-p256"),
        raises(TinyPkiError, "expire by its issuer's notAfter"),
    )
    cert_pem, _ = generate_intermediate_ca_certificate(*root, "Issuing CA", key_type="ec-p256", validity_days=364)
    not_after = x509.load_pem_x509_certificate(cert_pem).not_valid_after_utc
    assert_that(not_after <= x509.load_pem_x509_certificate(root[0]).not_valid_after_utc, is_(True))


def test_sign_intermediate_csr_uses_only_the_public_key_and_warns() -> None:
    csr_pem, key = _csr("requested name", with_ca_extension=True)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", TinyPkiWarning)
        cert_pem = sign_intermediate_csr(*_ROOT, csr_pem, "Issuing CA", permitted_subtrees=["lab.home.arpa"])
    cert = x509.load_pem_x509_certificate(cert_pem)
    assert_that(cert.public_key(), equal_to(key.public_key()))
    assert_that(cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, equal_to("Issuing CA"))
    assert_that(_basic_constraints(cert_pem).value.path_length, equal_to(0))
    assert_that(_permitted(cert_pem), equal_to(["lab.home.arpa"]))
    messages = " ".join(str(w.message) for w in caught)
    assert_that(messages, contains_string("requested name"))
    assert_that(messages, contains_string("intermediate CA"))


def test_pkcs12_carries_the_whole_chain() -> None:
    intermediate = generate_intermediate_ca_certificate(*_ROOT, "Issuing CA", key_type="ec-p256")
    leaf_pem, leaf_key = generate_server_certificate(*intermediate, "nas.home.arpa", ["nas.home.arpa"])
    p12 = generate_pkcs12(leaf_pem, leaf_key, intermediate[0] + _ROOT[0], "nas", b"fake-test-password-123")
    bundle = pkcs12.load_pkcs12(p12, b"fake-test-password-123")
    assert_that(bundle.additional_certs, has_length(2))


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not installed")
def test_openssl_verifies_the_chain(tmp_path: Path) -> None:
    intermediate = generate_intermediate_ca_certificate(*_ROOT, "Issuing CA", key_type="ec-p256")
    leaf_pem, _ = generate_server_certificate(*intermediate, "nas.home.arpa", ["nas.home.arpa"])
    (tmp_path / "root.pem").write_bytes(_ROOT[0])
    (tmp_path / "intermediate.pem").write_bytes(intermediate[0])
    (tmp_path / "leaf.pem").write_bytes(leaf_pem)
    result = subprocess.run(
        ["openssl", "verify", "-CAfile", "root.pem", "-untrusted", "intermediate.pem", "leaf.pem"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert_that(result.returncode, equal_to(0))
    assert_that(result.stdout, contains_string("leaf.pem: OK"))
