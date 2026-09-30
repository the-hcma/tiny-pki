"""Internal helpers for loading certificate signing requests and applying the signing policy."""

from __future__ import annotations

import hashlib

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from tiny_pki.constants import ALLOWED_KEY_SIZES
from tiny_pki.errors import TinyPkiError

PublicKey = rsa.RSAPublicKey | ec.EllipticCurvePublicKey

_ACCEPTED_SIGNATURE_HASHES = (hashes.SHA256, hashes.SHA384, hashes.SHA512)
_RSA_PUBLIC_EXPONENT = 65537
_PEM_CSR_MARKERS = (b"-----BEGIN CERTIFICATE REQUEST-----", b"-----BEGIN NEW CERTIFICATE REQUEST-----")


def is_csr_data(data: bytes) -> bool:
    """True when ``data`` is a PEM CSR (``CERTIFICATE REQUEST`` or ``NEW CERTIFICATE REQUEST``) or parses as DER."""
    if any(marker in data for marker in _PEM_CSR_MARKERS):
        return True
    if b"-----BEGIN" in data:
        return False
    try:
        x509.load_der_x509_csr(data)
    except ValueError:
        return False
    return True


def load_csr(data: bytes) -> x509.CertificateSigningRequest:
    """Load a PEM or DER certificate signing request.

    Windows ``certreq`` writes a ``NEW CERTIFICATE REQUEST`` PEM header; it is
    read like the standard ``CERTIFICATE REQUEST`` one.

    Raises:
        TinyPkiError: If ``data`` is not a CSR.
    """
    if not data.strip():
        raise TinyPkiError("Expected a certificate signing request, got empty input")
    try:
        if b"-----BEGIN" in data:
            return x509.load_pem_x509_csr(data.replace(b"NEW CERTIFICATE REQUEST", b"CERTIFICATE REQUEST"))
        return x509.load_der_x509_csr(data)
    except ValueError as exc:
        raise TinyPkiError(f"Expected a PEM or DER certificate signing request: {exc}") from exc


def csr_problems(csr: x509.CertificateSigningRequest) -> list[str]:
    """Return every reason the signing policy refuses ``csr`` (empty when it can be signed)."""
    problems: list[str] = []
    try:
        signature_valid = csr.is_signature_valid
    except (UnsupportedAlgorithm, ValueError):
        signature_valid = False
    if not signature_valid:
        problems.append("its signature does not verify against its own public key")
    try:
        algorithm = csr.signature_hash_algorithm
    except UnsupportedAlgorithm:
        algorithm = None
    if not isinstance(algorithm, _ACCEPTED_SIGNATURE_HASHES):
        name = algorithm.name if algorithm is not None else csr.signature_algorithm_oid.dotted_string
        problems.append(f"it is signed with {name}; expected SHA-256, SHA-384, or SHA-512")
    problem = _public_key_problem(csr)
    if problem is not None:
        problems.append(problem)
    try:
        _ = csr.extensions
    except ValueError as exc:
        problems.append(f"its requested extensions are malformed ({exc})")
    return problems


def requested_extension_names(csr: x509.CertificateSigningRequest) -> list[str]:
    """Names of the extensions a CSR requests (class names, or dotted OIDs for unrecognized ones)."""
    try:
        extensions = csr.extensions
    except ValueError:
        return []
    names: list[str] = []
    for extension in extensions:
        value = extension.value
        if isinstance(value, x509.UnrecognizedExtension):
            names.append(extension.oid.dotted_string)
        else:
            names.append(type(value).__name__)
    return names


def require_signable_public_key(csr: x509.CertificateSigningRequest) -> PublicKey:
    """Return the CSR's public key once :func:`csr_problems` finds nothing.

    Raises:
        TinyPkiError: Listing every policy problem with the CSR.
    """
    problems = csr_problems(csr)
    if problems:
        raise TinyPkiError(f"Expected a CSR tiny-pki can sign, but {'; '.join(problems)}")
    key = csr.public_key()
    if not isinstance(key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
        raise TinyPkiError(f"Expected an RSA or ECDSA P-256 public key in the CSR, got {type(key).__name__}")
    return key


def describe_public_key(key: object) -> tuple[str, int | None]:
    """Return ``(key_type, rsa_key_size)`` for display: ``("rsa", 3072)``, ``("ec-p256", None)``, or a description."""
    if isinstance(key, rsa.RSAPublicKey):
        return "rsa", key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        if isinstance(key.curve, ec.SECP256R1):
            return "ec-p256", None
        return f"ec ({key.curve.name})", None
    return type(key).__name__, None


def public_key_fingerprint(csr: x509.CertificateSigningRequest) -> str:
    """SHA-256 of the DER SubjectPublicKeyInfo as colon-separated hex.

    ``openssl pkey -pubin -outform DER`` produces the same bytes on the device.
    """
    spki = csr.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return ":".join(f"{b:02X}" for b in hashlib.sha256(spki).digest())


def _public_key_problem(csr: x509.CertificateSigningRequest) -> str | None:
    try:
        key = csr.public_key()
    except (UnsupportedAlgorithm, ValueError):
        return "its public key type is not supported"
    if isinstance(key, rsa.RSAPublicKey):
        if key.key_size not in ALLOWED_KEY_SIZES:
            return f"its RSA key is {key.key_size} bits; expected one of {ALLOWED_KEY_SIZES}"
        exponent = key.public_numbers().e
        if exponent != _RSA_PUBLIC_EXPONENT:
            return f"its RSA public exponent is {exponent}; expected {_RSA_PUBLIC_EXPONENT}"
        return None
    if isinstance(key, ec.EllipticCurvePublicKey):
        if not isinstance(key.curve, ec.SECP256R1):
            return f"its EC key is on {key.curve.name}; expected P-256 (secp256r1)"
        return None
    return f"its {type(key).__name__} key is not supported; expected RSA or ECDSA P-256"
