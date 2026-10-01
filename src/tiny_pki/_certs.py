"""Load an X.509 certificate from PEM or DER bytes."""

from __future__ import annotations

from cryptography import x509

from tiny_pki.errors import TinyPkiError


def load_certificate(data: bytes) -> x509.Certificate:
    """Load a PEM or DER certificate, such as the DER ``SSLObject.getpeercert(binary_form=True)`` returns.

    DER is tried first, because a DER certificate may itself contain ``-----BEGIN`` in a name or URI SAN;
    input that is not DER is read as PEM when it has a ``-----BEGIN`` header.
    The error never echoes the input, which may be any bytes a peer sent.

    Raises:
        TinyPkiError: If ``data`` is neither a PEM nor a DER certificate.
    """
    if not data.strip():
        raise TinyPkiError("Expected a PEM or DER X.509 certificate, got empty input")
    try:
        return x509.load_der_x509_certificate(data)
    except ValueError as der_exc:
        if b"-----BEGIN" not in data:
            raise TinyPkiError(
                f"Expected a PEM or DER X.509 certificate, got {len(data)} bytes that are not DER"
            ) from der_exc
    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError as exc:
        raise TinyPkiError("Expected a PEM or DER X.509 certificate, got PEM data that is not a certificate") from exc
