"""OCSP responses signed by the CA, and the OCSP URL in issued leaves (issue #160)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID
from hamcrest import assert_that, calling, close_to, equal_to, is_, raises

from tiny_pki import (
    KeyType,
    TinyPkiError,
    generate_ca_certificate,
    generate_client_certificate,
    generate_ocsp_response,
    generate_ocsp_response_for_certificate,
    generate_server_certificate,
    sign_client_csr,
    sign_server_csr,
)
from tiny_pki.ocsp import ForeignCertificateError

_CA_CERT, _CA_KEY = generate_ca_certificate("OCSP CA", key_type="ec-p256")
_OTHER_CA_CERT, _OTHER_CA_KEY = generate_ca_certificate("Other CA", key_type="ec-p256")
_SERVER_PEM, _ = generate_server_certificate(_CA_CERT, _CA_KEY, "api.home", ["api.home"], key_type="ec-p256")
_SERVER = x509.load_pem_x509_certificate(_SERVER_PEM)
_REVOKED_AT = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)


def _csr() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([]))
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


def _load(response_der: bytes, ca_cert_pem: bytes = _CA_CERT) -> ocsp.OCSPResponse:
    """Parse a successful response and check its signature against the CA key."""
    response = ocsp.load_der_ocsp_response(response_der)
    assert_that(response.response_status, equal_to(ocsp.OCSPResponseStatus.SUCCESSFUL))
    public_key = x509.load_pem_x509_certificate(ca_cert_pem).public_key()
    algorithm = response.signature_hash_algorithm
    assert algorithm is not None
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(response.signature, response.tbs_response_bytes, padding.PKCS1v15(), algorithm)
    else:
        assert isinstance(public_key, ec.EllipticCurvePublicKey)
        public_key.verify(response.signature, response.tbs_response_bytes, ec.ECDSA(algorithm))
    return response


def _ocsp_url_of(cert_pem: bytes) -> list[str]:
    try:
        aia = x509.load_pem_x509_certificate(cert_pem).extensions.get_extension_for_class(
            x509.AuthorityInformationAccess
        )
    except x509.ExtensionNotFound:
        return []
    return [str(d.access_location.value) for d in aia.value if d.access_method == AuthorityInformationAccessOID.OCSP]


def _request(
    cert: x509.Certificate = _SERVER,
    *,
    issuer_pem: bytes = _CA_CERT,
    algorithm: hashes.HashAlgorithm | None = None,
    nonce: bytes | None = None,
) -> bytes:
    issuer = x509.load_pem_x509_certificate(issuer_pem)
    builder = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, algorithm or hashes.SHA1())
    if nonce is not None:
        builder = builder.add_extension(x509.OCSPNonce(nonce), critical=False)
    return builder.build().public_bytes(serialization.Encoding.DER)


def _respond(request_der: bytes, *, issued: set[int], revoked: list[tuple[int, datetime]] | None = None) -> bytes:
    return generate_ocsp_response(_CA_CERT, _CA_KEY, request_der, issued_serials=issued, revoked_entries=revoked or [])


def test_a_foreign_certificate_cannot_be_pre_signed() -> None:
    foreign, _ = generate_server_certificate(
        _OTHER_CA_CERT, _OTHER_CA_KEY, "api.home", ["api.home"], key_type="ec-p256"
    )
    assert_that(
        calling(generate_ocsp_response_for_certificate).with_args(_CA_CERT, _CA_KEY, foreign, revoked_entries=[]),
        raises(ForeignCertificateError, "Expected a certificate issued by"),
    )


def test_a_malformed_request_gets_an_unsigned_malformed_response() -> None:
    response = ocsp.load_der_ocsp_response(_respond(b"not an OCSP request", issued=set()))
    assert_that(response.response_status, equal_to(ocsp.OCSPResponseStatus.MALFORMED_REQUEST))


def test_a_request_for_another_issuer_is_unauthorized() -> None:
    foreign_pem, _ = generate_server_certificate(
        _OTHER_CA_CERT, _OTHER_CA_KEY, "api.home", ["api.home"], key_type="ec-p256"
    )
    request = _request(x509.load_pem_x509_certificate(foreign_pem), issuer_pem=_OTHER_CA_CERT)
    response = ocsp.load_der_ocsp_response(_respond(request, issued={_SERVER.serial_number}))
    assert_that(response.response_status, equal_to(ocsp.OCSPResponseStatus.UNAUTHORIZED))


@pytest.mark.parametrize(("key_type", "key_size"), [("ec-p256", None), ("rsa", 2048)])
def test_issuer_hashes_match_what_clients_compute_for_each_ca_key_type(key_type: KeyType, key_size: int | None) -> None:
    ca_cert, ca_key = generate_ca_certificate("Key type CA", key_type=key_type, key_size=key_size)
    leaf_pem, _ = generate_client_certificate(ca_cert, ca_key, "alice", key_type="ec-p256")
    leaf = x509.load_pem_x509_certificate(leaf_pem)
    for algorithm in (hashes.SHA1(), hashes.SHA256()):
        request = _request(leaf, issuer_pem=ca_cert, algorithm=algorithm)
        response = _load(
            generate_ocsp_response(ca_cert, ca_key, request, issued_serials={leaf.serial_number}, revoked_entries=[]),
            ca_cert,
        )
        assert_that(response.certificate_status, equal_to(ocsp.OCSPCertStatus.GOOD))
        assert_that(response.hash_algorithm.name, equal_to(algorithm.name))


def test_leaves_carry_the_ocsp_url_only_when_given() -> None:
    url = "http://ocsp.home/"
    client, _ = generate_client_certificate(_CA_CERT, _CA_KEY, "alice", key_type="ec-p256", ocsp_url=url)
    server, _ = generate_server_certificate(
        _CA_CERT, _CA_KEY, "api.home", ["api.home"], key_type="ec-p256", ocsp_url=f"  {url} "
    )
    signed_client = sign_client_csr(_CA_CERT, _CA_KEY, _csr(), "bob", ocsp_url=url)
    signed_server = sign_server_csr(_CA_CERT, _CA_KEY, _csr(), "web.home", ["web.home"], ocsp_url=url)
    for cert_pem in (client, server, signed_client, signed_server):
        assert_that(_ocsp_url_of(cert_pem), equal_to([url]))
    assert_that(_ocsp_url_of(_SERVER_PEM), equal_to([]))


@pytest.mark.parametrize(
    "url", ["ftp://ocsp.home/", "http://", "ocsp.home", "http://ocsp.home/a b", "http://ocsp.hóme/"]
)
def test_leaves_refuse_an_ocsp_url_that_is_not_http(url: str) -> None:
    assert_that(
        calling(generate_client_certificate).with_args(_CA_CERT, _CA_KEY, "alice", key_type="ec-p256", ocsp_url=url),
        raises(TinyPkiError, "Expected an http:// or https:// URL"),
    )


def test_pre_signed_response_says_good_or_revoked() -> None:
    good = _load(generate_ocsp_response_for_certificate(_CA_CERT, _CA_KEY, _SERVER_PEM, revoked_entries=[]))
    assert_that(good.certificate_status, equal_to(ocsp.OCSPCertStatus.GOOD))
    assert_that(good.serial_number, equal_to(_SERVER.serial_number))
    revoked = _load(
        generate_ocsp_response_for_certificate(
            _CA_CERT, _CA_KEY, _SERVER_PEM, revoked_entries=[(_SERVER.serial_number, _REVOKED_AT)]
        )
    )
    assert_that(revoked.certificate_status, equal_to(ocsp.OCSPCertStatus.REVOKED))
    assert_that(revoked.revocation_time_utc, equal_to(_REVOKED_AT))


def test_request_nonce_is_echoed() -> None:
    response = _load(_respond(_request(nonce=b"\x04\x10" + b"n" * 16), issued={_SERVER.serial_number}))
    nonce = response.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
    assert_that(nonce, equal_to(b"\x04\x10" + b"n" * 16))


def test_response_lifetime_follows_validity_days() -> None:
    response = _load(
        generate_ocsp_response(
            _CA_CERT, _CA_KEY, _request(), issued_serials={_SERVER.serial_number}, revoked_entries=[], validity_days=2
        )
    )
    assert response.next_update_utc is not None
    lifetime = response.next_update_utc - response.this_update_utc
    assert_that(lifetime.total_seconds(), close_to(timedelta(days=2, minutes=5).total_seconds(), 5))
    assert_that(response.this_update_utc < datetime.now(UTC), is_(True))
    for days in (0, 31, True):
        assert_that(
            calling(generate_ocsp_response).with_args(
                _CA_CERT, _CA_KEY, _request(), issued_serials=set(), revoked_entries=[], validity_days=days
            ),
            raises(TinyPkiError, "between 1 and 30 days"),
        )


def test_status_is_good_revoked_or_unknown() -> None:
    serial = _SERVER.serial_number
    good = _load(_respond(_request(), issued={serial}))
    assert_that(good.certificate_status, equal_to(ocsp.OCSPCertStatus.GOOD))

    revoked = _load(_respond(_request(), issued={serial}, revoked=[(serial, _REVOKED_AT)]))
    assert_that(revoked.certificate_status, equal_to(ocsp.OCSPCertStatus.REVOKED))
    assert_that(revoked.revocation_time_utc, equal_to(_REVOKED_AT))

    unknown = _load(_respond(_request(), issued={serial + 1}))
    assert_that(unknown.certificate_status, equal_to(ocsp.OCSPCertStatus.UNKNOWN))
    assert_that(unknown.responder_key_hash is not None, is_(True))
