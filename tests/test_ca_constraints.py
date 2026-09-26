"""CA path length and Name Constraints (issue #32)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import ipaddress
import warnings
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from hamcrest import assert_that, calling, contains_string, equal_to, has_item, is_, none, raises
from pytest import CaptureFixture
from pytest import raises as pytest_raises

from tiny_pki import (
    TinyPkiError,
    TinyPkiWarning,
    generate_ca_certificate,
    generate_client_certificate,
    generate_server_certificate,
    get_certificate_sans,
)
from tiny_pki._rsa import load_rsa_private_key
from tiny_pki.cli.main import main
from tiny_pki.store import CertificateStore

_CONSTRAINED = generate_ca_certificate(
    "Home CA", key_size=2048, permitted_subtrees=["Home", "192.168.0.0/16", "10.0.0.7"]
)


def test_ca_is_limited_to_leaves() -> None:
    ca_cert, _ = generate_ca_certificate(key_size=2048)
    cert = x509.load_pem_x509_certificate(ca_cert)
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert_that(bc.path_length, equal_to(0))
    assert_that(
        calling(cert.extensions.get_extension_for_class).with_args(x509.NameConstraints),
        raises(x509.ExtensionNotFound),
    )


def test_ca_name_constraints_extension() -> None:
    cert = x509.load_pem_x509_certificate(_CONSTRAINED[0])
    ext = cert.extensions.get_extension_for_class(x509.NameConstraints)
    assert_that(ext.critical, is_(True))
    assert_that(ext.value.excluded_subtrees, none())
    assert_that(
        list(ext.value.permitted_subtrees or []),
        equal_to(
            [
                x509.DNSName("home"),
                x509.IPAddress(ipaddress.ip_network("192.168.0.0/16")),
                x509.IPAddress(ipaddress.ip_network("10.0.0.7/32")),
            ]
        ),
    )


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        ("", "non-empty permitted subtree"),
        ("*.home", "without wildcards"),
        ("192.168.1.10/24", "without host bits"),
        ("https://home", "not a URL"),
        (".home", "without a leading dot"),
    ],
)
def test_ca_rejects_invalid_permitted_subtree(entry: str, message: str) -> None:
    assert_that(
        calling(generate_ca_certificate).with_args(key_size=2048, permitted_subtrees=[entry]),
        raises(TinyPkiError, message),
    )


def test_cli_init_permit_and_reject_outside(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    store = tmp_path / "ca"
    _cli(store, "init", "--key-size", "2048", "--permit", "home", "--permit", "192.168.0.0/16")
    cert = x509.load_pem_x509_certificate(CertificateStore(store).read_ca()[0])
    constraints = cert.extensions.get_extension_for_class(x509.NameConstraints).value
    assert_that(len(list(constraints.permitted_subtrees or [])), equal_to(2))
    capsys.readouterr()

    _cli(store, "create", "server", "api.home", "--key-size", "2048")
    with pytest_raises(SystemExit):
        _cli(store, "create", "server", "api.example", "--key-size", "2048")
    assert_that(capsys.readouterr().err, contains_string("within the CA's permitted names"))


def test_client_cn_checked_only_when_host_like() -> None:
    ca_cert, ca_key = _CONSTRAINED
    generate_client_certificate(ca_cert, ca_key, "alice", key_size=2048)
    generate_client_certificate(ca_cert, ca_key, "phone.alice.home", key_size=2048)
    assert_that(
        calling(generate_client_certificate).with_args(ca_cert, ca_key, "phone.example", key_size=2048),
        raises(TinyPkiError, "within the CA's permitted names"),
    )


def test_leading_dot_constraint_excludes_apex() -> None:
    ca_cert, ca_key = _external_ca_with_dns_constraint(".example.com")
    generate_server_certificate(ca_cert, ca_key, "api.example.com", ["api.example.com"], key_size=2048)
    assert_that(
        calling(generate_server_certificate).with_args(ca_cert, ca_key, "example.com", ["example.com"], key_size=2048),
        raises(TinyPkiError, "within the CA's permitted names"),
    )


def test_server_sans_must_fit_constraints() -> None:
    ca_cert, ca_key = _CONSTRAINED
    cert_pem, _ = generate_server_certificate(
        ca_cert, ca_key, "api.home", ["*.lan.home", "home", "api.home", "192.168.4.2", "10.0.0.7"], key_size=2048
    )
    assert_that(get_certificate_sans(cert_pem), equal_to(["*.lan.home", "home", "api.home", "192.168.4.2", "10.0.0.7"]))
    for sans, message in (
        (["api.example"], "within the CA's permitted names"),
        (["evilhome"], "within the CA's permitted names"),
        (["10.0.0.8"], "within the CA's permitted networks"),
        (["::1"], "within the CA's permitted networks"),
    ):
        assert_that(
            calling(generate_server_certificate).with_args(
                ca_cert, ca_key, "api.home", sans, key_size=2048, include_common_name_in_sans=False
            ),
            raises(TinyPkiError, message),
        )


@pytest.mark.parametrize("common_name", ["api.example", "api_foo.example", "203.0.113.7", "Evil_Example.COM."])
def test_server_host_like_cn_checked_without_dns_san(common_name: str) -> None:
    ca_cert, ca_key = _CONSTRAINED
    assert_that(
        calling(generate_server_certificate).with_args(
            ca_cert, ca_key, common_name, ["192.168.1.1"], key_size=2048, include_common_name_in_sans=False
        ),
        raises(TinyPkiError, "within the CA's permitted names"),
    )
    assert_that(
        calling(generate_client_certificate).with_args(ca_cert, ca_key, common_name, key_size=2048),
        raises(TinyPkiError, "within the CA's permitted names"),
    )
    generate_client_certificate(ca_cert, ca_key, "alice_phone.home", key_size=2048)
    generate_client_certificate(ca_cert, ca_key, "Alice Smith (phone)", key_size=2048)


_DNS_ONLY = generate_ca_certificate("DNS CA", key_size=2048, permitted_subtrees=["home"])
_IP_ONLY = generate_ca_certificate("IP CA", key_size=2048, permitted_subtrees=["192.168.0.0/16"])


def test_dns_only_ca_refuses_ip_sans() -> None:
    assert_that(
        calling(generate_server_certificate).with_args(*_DNS_ONLY, "api.home", ["api.home", "8.8.8.8"], key_size=2048),
        raises(TinyPkiError, "without a permitted IP subtree"),
    )


def test_dns_only_ca_issues_dns_sans() -> None:
    cert_pem, _ = generate_server_certificate(*_DNS_ONLY, "api.home", ["api.home"], key_size=2048)
    assert_that(get_certificate_sans(cert_pem), equal_to(["api.home"]))


def test_dns_only_ca_skips_ip_literal_cn_with_warning() -> None:
    with pytest.warns(TinyPkiWarning, match="Did not add common_name '10.0.0.9'"):
        cert_pem, _ = generate_server_certificate(*_DNS_ONLY, "10.0.0.9", ["api.home"], key_size=2048)
    assert_that(get_certificate_sans(cert_pem), equal_to(["api.home"]))


def test_ip_only_ca_refuses_dns_sans() -> None:
    assert_that(
        calling(generate_server_certificate).with_args(
            *_IP_ONLY, "router", ["google.com", "192.168.1.10"], key_size=2048
        ),
        raises(TinyPkiError, "without a permitted DNS subtree"),
    )


def test_ip_only_ca_refuses_dotted_cn_without_dns_san() -> None:
    assert_that(
        calling(generate_server_certificate).with_args(*_IP_ONLY, "google.com", ["192.168.1.10"], key_size=2048),
        raises(TinyPkiError, "without a permitted DNS subtree"),
    )
    assert_that(
        calling(generate_client_certificate).with_args(*_IP_ONLY, "alice.example.com", key_size=2048),
        raises(TinyPkiError, "without a permitted DNS subtree"),
    )


def test_ip_only_ca_issues_ip_sans_and_plain_client_cns() -> None:
    cert_pem, _ = generate_server_certificate(*_IP_ONLY, "router", ["192.168.1.10"], key_size=2048)
    assert_that(get_certificate_sans(cert_pem), equal_to(["192.168.1.10"]))
    generate_client_certificate(*_IP_ONLY, "alice", key_size=2048)


def test_ip_only_ca_issues_ip_literal_cn() -> None:
    cert_pem, _ = generate_server_certificate(*_IP_ONLY, "192.168.1.10", ["192.168.1.10"], key_size=2048)
    assert_that(get_certificate_sans(cert_pem), equal_to(["192.168.1.10"]))
    generate_client_certificate(*_IP_ONLY, "192.168.1.11", key_size=2048)


def test_ip_only_ca_refuses_out_of_range_ip_literal_cn() -> None:
    assert_that(
        calling(generate_client_certificate).with_args(*_IP_ONLY, "8.8.8.8", key_size=2048),
        raises(TinyPkiError, "within the CA's permitted networks"),
    )
    assert_that(
        calling(generate_server_certificate).with_args(
            *_IP_ONLY, "8.8.8.8", ["192.168.1.10"], key_size=2048, include_common_name_in_sans=False
        ),
        raises(TinyPkiError, "within the CA's permitted networks"),
    )


def test_dns_only_ca_does_not_add_ip_literal_cn_as_san() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        cert_pem, _ = generate_server_certificate(*_DNS_ONLY, "192.168.1.10", ["api.home"], key_size=2048)
    assert_that(get_certificate_sans(cert_pem), equal_to(["api.home"]))
    messages = [str(w.message) for w in caught if issubclass(w.category, TinyPkiWarning)]
    assert_that(messages, has_item(contains_string("Did not add common_name")))


def test_cli_ip_only_ca_refuses_public_hostname(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    store = tmp_path / "store"
    _cli(store, "init", "--cn", "IP CA", "--key-size", "2048", "--permit", "192.168.0.0/16")
    capsys.readouterr()
    with pytest_raises(SystemExit):
        _cli(store, "create", "server", "google.com", "--san", "192.168.1.10", "--key-size", "2048", "--yes")
    assert_that(capsys.readouterr().err, contains_string("without a permitted DNS subtree"))
    assert_that(CertificateStore(store).list_certificates(), equal_to([]))


def test_cli_ip_only_ca_issues_host_cn_with_ip_san(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    store = tmp_path / "store"
    _cli(store, "init", "--cn", "IP CA", "--key-size", "2048", "--permit", "192.168.0.0/16")
    _cli(store, "create", "server", "router", "--san", "192.168.1.10", "--key-size", "2048", "--yes")
    assert_that(capsys.readouterr().err, contains_string("Did not add common_name 'router'"))
    entry = CertificateStore(store).get_certificate("router")
    assert entry is not None
    cert_pem = CertificateStore(store).read_certificate_pem(entry)
    assert_that(get_certificate_sans(cert_pem), equal_to(["192.168.1.10"]))


def test_cli_ip_only_ca_needs_an_ip_san_for_a_host_cn(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    store = tmp_path / "store"
    _cli(store, "init", "--cn", "IP CA", "--key-size", "2048", "--permit", "192.168.0.0/16")
    capsys.readouterr()
    with pytest_raises(SystemExit):
        _cli(store, "create", "server", "router", "--key-size", "2048", "--yes")
    assert_that(capsys.readouterr().err, contains_string("without a permitted DNS subtree"))
    assert_that(CertificateStore(store).list_certificates(), equal_to([]))


def _cli(store: Path, *words: str) -> None:
    main(["--store", str(store), "--color", "never", *words])


def _external_ca_with_dns_constraint(root: str) -> tuple[bytes, bytes]:
    """A CA built outside tiny-pki, keeping the constraint's leading dot verbatim."""
    return _external_ca([x509.DNSName(root)], None)


def _external_ca(
    permitted: list[x509.GeneralName] | None, excluded: list[x509.GeneralName] | None
) -> tuple[bytes, bytes]:
    _, key_pem = _CONSTRAINED
    key = load_rsa_private_key(key_pem)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "External CA")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.NameConstraints(permitted_subtrees=permitted, excluded_subtrees=excluded), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM), key_pem


def _ip(text: str) -> x509.IPAddress:
    return x509.IPAddress(ipaddress.ip_network(text))


def test_excluded_ipv4_also_excludes_its_mapped_ipv6_form() -> None:
    ca = _external_ca([_ip("0.0.0.0/0"), _ip("::/0")], [_ip("10.0.0.0/8")])
    for san in ("10.1.2.3", "::ffff:10.1.2.3"):
        assert_that(
            calling(generate_server_certificate).with_args(*ca, "host", [san], key_size=2048),
            raises(TinyPkiError, "excluded networks"),
        )
    generate_server_certificate(*ca, "host", ["::ffff:192.168.1.1"], key_size=2048)


def test_mapped_ipv6_constraint_applies_to_plain_ipv4() -> None:
    ca = _external_ca([_ip("0.0.0.0/0"), _ip("::/0")], [_ip("::ffff:10.0.0.0/104")])
    assert_that(
        calling(generate_server_certificate).with_args(*ca, "host", ["10.1.2.3"], key_size=2048),
        raises(TinyPkiError, "excluded networks"),
    )


def test_permitted_ipv4_does_not_admit_its_mapped_ipv6_form() -> None:
    assert_that(
        calling(generate_server_certificate).with_args(*_IP_ONLY, "router", ["::ffff:192.168.1.10"], key_size=2048),
        raises(TinyPkiError, "permitted networks"),
    )
