"""OCSP responses signed by the CA (RFC 6960), DER bytes in / out.

tiny-pki runs no responder. :func:`generate_ocsp_response` answers one request
(for a consumer's own HTTP endpoint), and
:func:`generate_ocsp_response_for_certificate` pre-signs a response a TLS server
can staple. Both read the same ``(serial, revoked_at)`` data as
:func:`tiny_pki.generate_crl`, so the two never disagree.
"""

from __future__ import annotations

from collections.abc import Collection
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import ocsp

from tiny_pki._keys import load_ca_private_key
from tiny_pki.constants import CLOCK_SKEW_BACKDATE, DEFAULT_OCSP_VALIDITY_DAYS, MAX_OCSP_VALIDITY_DAYS
from tiny_pki.errors import TinyPkiError


class ForeignCertificateError(TinyPkiError):
    """The certificate given to :func:`generate_ocsp_response_for_certificate` was not issued by the CA."""


def generate_ocsp_response(
    ca_cert_pem: bytes,
    ca_key_pem: bytes,
    request_der: bytes,
    *,
    issued_serials: Collection[int],
    revoked_entries: list[tuple[int, datetime]],
    validity_days: int = DEFAULT_OCSP_VALIDITY_DAYS,
) -> bytes:
    """Answer one DER OCSP request with a response signed by the CA key.

    The status is ``revoked`` (with its time) for a serial in ``revoked_entries``,
    ``good`` for one in ``issued_serials``, and ``unknown`` otherwise, so a serial
    the CA never issued is not vouched for. A request for another issuer gets an
    ``unauthorized`` response, and one that does not parse gets
    ``malformedRequest``; both are unsigned, as RFC 6960 specifies. A request
    nonce is echoed back. The response is valid from now (backdated by
    ``CLOCK_SKEW_BACKDATE``) for ``validity_days``.

    Returns:
        The DER-encoded OCSP response.

    Raises:
        TinyPkiError: If ``validity_days`` is outside 1..``MAX_OCSP_VALIDITY_DAYS``
            or the CA key does not match the CA certificate.
    """
    _require_ocsp_validity_days(validity_days)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key = load_ca_private_key(ca_cert, ca_key_pem)
    try:
        request = ocsp.load_der_ocsp_request(request_der)
        algorithm = request.hash_algorithm
    except (ValueError, UnsupportedAlgorithm):
        return _unsuccessful(ocsp.OCSPResponseStatus.MALFORMED_REQUEST)
    name_hash, key_hash = _issuer_hashes(ca_cert, algorithm)
    if (request.issuer_name_hash, request.issuer_key_hash) != (name_hash, key_hash):
        return _unsuccessful(ocsp.OCSPResponseStatus.UNAUTHORIZED)

    serial = request.serial_number
    revoked_at = dict(revoked_entries).get(serial)
    if revoked_at is not None:
        status = ocsp.OCSPCertStatus.REVOKED
    elif serial in issued_serials:
        status = ocsp.OCSPCertStatus.GOOD
    else:
        status = ocsp.OCSPCertStatus.UNKNOWN
    now = datetime.now(UTC)
    builder = ocsp.OCSPResponseBuilder().add_response_by_hash(
        issuer_name_hash=name_hash,
        issuer_key_hash=key_hash,
        serial_number=serial,
        algorithm=algorithm,
        cert_status=status,
        this_update=now - CLOCK_SKEW_BACKDATE,
        next_update=now + timedelta(days=validity_days),
        revocation_time=revoked_at,
        revocation_reason=None,
    )
    try:
        nonce = request.extensions.get_extension_for_class(x509.OCSPNonce).value
    except x509.ExtensionNotFound:
        pass
    else:
        builder = builder.add_extension(nonce, critical=False)
    response = builder.responder_id(ocsp.OCSPResponderEncoding.HASH, ca_cert).sign(ca_key, hashes.SHA256())
    return response.public_bytes(serialization.Encoding.DER)


def generate_ocsp_response_for_certificate(
    ca_cert_pem: bytes,
    ca_key_pem: bytes,
    cert_pem: bytes,
    *,
    revoked_entries: list[tuple[int, datetime]],
    validity_days: int = DEFAULT_OCSP_VALIDITY_DAYS,
) -> bytes:
    """Pre-sign the OCSP response for ``cert_pem``, for a TLS server to staple.

    The response is what :func:`generate_ocsp_response` returns for a SHA-1
    CertID request (the form OpenSSL and nginx send), so it is ``revoked`` when
    the serial is in ``revoked_entries`` and ``good`` otherwise.

    Returns:
        The DER-encoded OCSP response (nginx ``ssl_stapling_file``).

    Raises:
        ForeignCertificateError: If ``cert_pem`` was not issued by this CA.
        TinyPkiError: For any reason :func:`generate_ocsp_response` raises.
    """
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    cert = x509.load_pem_x509_certificate(cert_pem)
    try:
        cert.verify_directly_issued_by(ca_cert)
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise ForeignCertificateError(
            f"Expected a certificate issued by {ca_cert.subject.rfc4514_string()}, got one issued by "
            f"{cert.issuer.rfc4514_string()}"
        ) from exc
    request = ocsp.OCSPRequestBuilder().add_certificate(cert, ca_cert, hashes.SHA1()).build()
    return generate_ocsp_response(
        ca_cert_pem,
        ca_key_pem,
        request.public_bytes(serialization.Encoding.DER),
        issued_serials={cert.serial_number},
        revoked_entries=revoked_entries,
        validity_days=validity_days,
    )


def _issuer_hashes(ca_cert: x509.Certificate, algorithm: hashes.HashAlgorithm) -> tuple[bytes, bytes]:
    """CertID ``issuerNameHash`` and ``issuerKeyHash``: the subject DER and the subjectPublicKey BIT STRING contents."""
    public_key = ca_cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        key_bits = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        key_bits = public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    else:
        raise TinyPkiError(f"Expected an RSA or ECDSA CA key, got {type(public_key).__name__}")
    return _digest(algorithm, ca_cert.subject.public_bytes()), _digest(algorithm, key_bits)


def _digest(algorithm: hashes.HashAlgorithm, data: bytes) -> bytes:
    digest = hashes.Hash(algorithm)
    digest.update(data)
    return digest.finalize()


def _require_ocsp_validity_days(validity_days: int) -> None:
    if isinstance(validity_days, bool) or not 0 < validity_days <= MAX_OCSP_VALIDITY_DAYS:
        raise TinyPkiError(
            f"Expected an OCSP response lifetime between 1 and {MAX_OCSP_VALIDITY_DAYS} days, got {validity_days}"
        )


def _unsuccessful(status: ocsp.OCSPResponseStatus) -> bytes:
    return ocsp.OCSPResponseBuilder.build_unsuccessful(status).public_bytes(serialization.Encoding.DER)
