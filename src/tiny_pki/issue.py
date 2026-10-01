"""Issue CA, server, and client certificates (PEM bytes in / out).

Extracted and generalized from ``the-hcma/my-tracks`` ``app/pki.py`` (MIT).
"""

from __future__ import annotations

import ipaddress
import re
import warnings
from datetime import UTC, datetime, timedelta
from typing import Literal
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID

from tiny_pki._csr import (
    PublicKey,
    load_csr,
    requested_extension_names,
    requested_sans,
    require_signable_public_key,
    unsupported_requested_sans,
)
from tiny_pki._keys import PrivateKey, generate_private_key, load_ca_private_key, require_key_params
from tiny_pki.constants import (
    APPLE_MAX_SERVER_VALIDITY_DAYS,
    CLOCK_SKEW_BACKDATE,
    DEFAULT_CA_KEY_SIZE,
    DEFAULT_CA_VALIDITY_DAYS,
    DEFAULT_CLIENT_VALIDITY_DAYS,
    DEFAULT_INTERMEDIATE_VALIDITY_DAYS,
    DEFAULT_KEY_TYPE,
    DEFAULT_LEAF_KEY_SIZE,
    DEFAULT_ORGANIZATION_NAME,
    DEFAULT_SERVER_VALIDITY_DAYS,
    MAX_CLIENT_VALIDITY_DAYS,
    MAX_SERVER_VALIDITY_DAYS,
    MAX_VALIDITY_DAYS,
    URI_SUBTREE_PREFIX,
    KeyType,
)
from tiny_pki.errors import TinyPkiError, TinyPkiWarning
from tiny_pki.names import (
    MAX_COMMON_NAME_LENGTH,
    MAX_ORGANIZATION_NAME_LENGTH,
    common_name_as_san,
    normalize_dns_name,
    normalize_http_url,
    normalize_san_entries,
    normalize_san_entry,
    normalize_subject_attribute,
    normalize_uri_san,
)


def generate_ca_certificate(
    common_name: str = "Private CA",
    *,
    organization_name: str = DEFAULT_ORGANIZATION_NAME,
    validity_days: int = DEFAULT_CA_VALIDITY_DAYS,
    key_size: int | None = None,
    key_type: KeyType = DEFAULT_KEY_TYPE,
    permitted_subtrees: list[str] | None = None,
    path_length: int = 0,
) -> tuple[bytes, bytes]:
    """Generate a self-signed CA certificate and private key.

    With the default ``path_length=0`` the CA may only sign leaves
    (``BasicConstraints(path_length=0)``). ``path_length=1`` makes a root that can
    also sign intermediate CAs (see :func:`generate_intermediate_ca_certificate`),
    so its key can stay offline while an intermediate issues the leaves.
    ``permitted_subtrees`` optionally restricts it with a critical Name Constraints
    extension: DNS suffixes (``"home"`` permits ``home`` and ``*.home``) and IP
    networks (``"192.168.0.0/16"``; a bare IP means a single host), plus URI hosts
    for URI SANs (``"uri:example.home"`` permits URIs whose host is exactly
    ``example.home``, ``"uri:.example.home"`` any host under it). RFC 5280
    constraints only apply to the name types listed, so include IP ranges too if
    leaves will carry IP SANs.

    The validity window is backdated by ``CLOCK_SKEW_BACKDATE`` so relying parties
    with slightly slow clocks accept the certificate immediately; the encoded
    period stays exactly ``validity_days``.

    ``key_type`` is ``"rsa"`` (``key_size`` bits, default ``DEFAULT_CA_KEY_SIZE``)
    or ``"ec-p256"`` (ECDSA P-256; ``key_size`` must be omitted). The CA and its
    leaves may use different key types.

    Returns:
        Tuple of ``(certificate_pem, private_key_pem)``.

    Raises:
        TinyPkiError: If ``key_type`` is unknown, ``key_size`` is not in
            ``ALLOWED_KEY_SIZES`` (or is given for ``"ec-p256"``), a name is
            empty, too long, or contains control characters, a permitted subtree
            is invalid, or ``path_length`` is not 0 or 1.
    """
    common_name = normalize_subject_attribute(common_name, "common_name", max_length=MAX_COMMON_NAME_LENGTH)
    organization_name = normalize_subject_attribute(
        organization_name, "organization_name", max_length=MAX_ORGANIZATION_NAME_LENGTH
    )
    rsa_key_size = require_key_params(key_type, key_size, default_size=DEFAULT_CA_KEY_SIZE)
    _require_validity_days(validity_days)
    if isinstance(path_length, bool) or path_length not in (0, 1):
        raise TinyPkiError(
            "Expected path_length 0 (the CA signs leaves) or 1 (it also signs intermediate CAs, which sign leaves), "
            f"got {path_length!r}"
        )
    subtrees = [_permitted_subtree(entry) for entry in permitted_subtrees or []]

    key = generate_private_key(rsa_key_size)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        ]
    )
    not_before, not_after = _validity_window(validity_days)
    builder = x509.CertificateBuilder()
    if subtrees:
        builder = builder.add_extension(
            x509.NameConstraints(permitted_subtrees=subtrees, excluded_subtrees=None), critical=True
        )
    cert = (
        builder.subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return _pem_pair(cert, key)


def generate_client_certificate(
    ca_cert_pem: bytes,
    ca_key_pem: bytes,
    common_name: str,
    *,
    organization_name: str | None = None,
    validity_days: int = DEFAULT_CLIENT_VALIDITY_DAYS,
    key_size: int | None = None,
    key_type: KeyType = DEFAULT_KEY_TYPE,
    allow_long_validity: bool = False,
    allow_dn_special_chars: bool = False,
    ocsp_url: str | None = None,
    uri_san: str | None = None,
) -> tuple[bytes, bytes]:
    """Generate a client (CLIENT_AUTH) certificate signed by the given CA.

    ``common_name`` is the identity embedded in the CN (person, device, or service).
    A CN containing an RFC 4514 special character (``,`` ``+`` ``=`` ``"`` ``<``
    ``>`` ``;`` or a leading ``#``) is refused unless ``allow_dn_special_chars=True``,
    because it can make the subject DN string look like another identity.

    When ``organization_name`` is omitted, the CA certificate's O is reused, falling
    back to ``DEFAULT_ORGANIZATION_NAME`` if the CA has no O attribute.

    ``key_type`` / ``key_size`` work as for :func:`generate_ca_certificate`, with
    ``DEFAULT_LEAF_KEY_SIZE`` as the RSA default. ECDSA leaves omit
    ``keyEncipherment`` from Key Usage (RFC 8813), RSA leaves keep it.

    ``ocsp_url`` (``http://`` or ``https://``) adds an Authority Information
    Access extension pointing relying parties at that OCSP responder; see
    :mod:`tiny_pki.ocsp`. Every leaf-issuing function accepts it.

    ``uri_san`` adds exactly one URI Subject Alternative Name, such as the SPIFFE
    ID ``spiffe://example.home/device/phone-1`` that SPIFFE-aware relying parties
    (Envoy, amqtt's ``UserAuthCertPlugin``) authenticate on. The CN stays the
    identity for CN-based relying parties such as nginx and Mosquitto. See
    :func:`tiny_pki.names.normalize_uri_san` for the accepted URIs; under a CA
    with Name Constraints the URI's host must lie within a permitted URI subtree
    (``permitted_subtrees`` entry ``uri:HOST``).

    Raises:
        TinyPkiError: If a name, key parameter, ``ocsp_url`` or ``uri_san`` is invalid, ``validity_days`` exceeds
            ``MAX_CLIENT_VALIDITY_DAYS`` without ``allow_long_validity=True``, or the
            certificate would outlive the CA.
    """
    common_name = normalize_subject_attribute(common_name, "common_name", max_length=MAX_COMMON_NAME_LENGTH)
    if not allow_dn_special_chars:
        _require_plain_common_name(common_name)
    rsa_key_size = require_key_params(key_type, key_size, default_size=DEFAULT_LEAF_KEY_SIZE)
    _require_validity_days(validity_days)
    ocsp_url = _ocsp_url(ocsp_url)
    uri_san = None if uri_san is None else normalize_uri_san(uri_san)

    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key = load_ca_private_key(ca_cert, ca_key_pem)
    org = _leaf_organization(ca_cert, organization_name)
    _enforce_name_constraints(ca_cert, common_name=common_name, sans=[], uris=[uri_san] if uri_san else [])
    pending_warnings: list[str] = []
    not_before, not_after = _leaf_validity_window(
        ca_cert, validity_days, kind="client", allow_long_validity=allow_long_validity, warn=pending_warnings
    )
    client_key = generate_private_key(rsa_key_size)
    cert = _client_certificate(
        ca_cert,
        ca_key,
        client_key.public_key(),
        common_name=common_name,
        organization_name=org,
        not_before=not_before,
        not_after=not_after,
        ocsp_url=ocsp_url,
        uri_san=uri_san,
    )
    _emit_warnings(pending_warnings)
    return _pem_pair(cert, client_key)


def sign_client_csr(
    ca_cert_pem: bytes,
    ca_key_pem: bytes,
    csr_pem: bytes,
    common_name: str,
    *,
    organization_name: str | None = None,
    validity_days: int = DEFAULT_CLIENT_VALIDITY_DAYS,
    allow_long_validity: bool = False,
    allow_dn_special_chars: bool = False,
    ocsp_url: str | None = None,
    uri_san: str | None = None,
) -> bytes:
    """Sign a device's certificate signing request as a client (CLIENT_AUTH) certificate.

    The private key stays wherever the CSR was generated; only its public key is
    taken from ``csr_pem`` (PEM or DER). Everything else comes from the CA side,
    exactly as in :func:`generate_client_certificate`: ``common_name`` (never the
    CSR's subject), ``uri_san`` (never a SAN the CSR requests), the organization,
    the validity window, and the extensions.
    Extensions the CSR requests, such as ``BasicConstraints(ca=True)`` or extra
    extended key usages, are ignored, so a CSR cannot obtain a CA or server
    certificate.

    The CSR must carry a valid self-signature using SHA-256, SHA-384, or SHA-512,
    and an RSA key of an ``ALLOWED_KEY_SIZES`` size or an ECDSA P-256 key.

    Returns:
        The certificate in PEM format.

    Raises:
        TinyPkiError: If the CSR is malformed or fails that policy, or for any
            reason :func:`generate_client_certificate` would refuse the name or
            validity.

    Warns:
        TinyPkiWarning: When the CSR's subject CN differs from ``common_name``, or
            the CSR requests extensions; both are ignored. Warnings are emitted only
            after the certificate is issued, never for a rejection.
    """
    common_name = normalize_subject_attribute(common_name, "common_name", max_length=MAX_COMMON_NAME_LENGTH)
    if not allow_dn_special_chars:
        _require_plain_common_name(common_name)
    _require_validity_days(validity_days)
    ocsp_url = _ocsp_url(ocsp_url)
    uri_san = None if uri_san is None else normalize_uri_san(uri_san)
    csr = load_csr(csr_pem)
    public_key = require_signable_public_key(csr)

    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key = load_ca_private_key(ca_cert, ca_key_pem)
    org = _leaf_organization(ca_cert, organization_name)
    _enforce_name_constraints(ca_cert, common_name=common_name, sans=[], uris=[uri_san] if uri_san else [])
    pending_warnings = _ignored_csr_request_warnings(csr, common_name, profile="client")
    not_before, not_after = _leaf_validity_window(
        ca_cert, validity_days, kind="client", allow_long_validity=allow_long_validity, warn=pending_warnings
    )
    cert = _client_certificate(
        ca_cert,
        ca_key,
        public_key,
        common_name=common_name,
        organization_name=org,
        not_before=not_before,
        not_after=not_after,
        ocsp_url=ocsp_url,
        uri_san=uri_san,
    )
    _emit_warnings(pending_warnings)
    return cert.public_bytes(serialization.Encoding.PEM)


def generate_server_certificate(
    ca_cert_pem: bytes,
    ca_key_pem: bytes,
    common_name: str,
    san_entries: list[str],
    *,
    organization_name: str | None = None,
    validity_days: int = DEFAULT_SERVER_VALIDITY_DAYS,
    key_size: int | None = None,
    key_type: KeyType = DEFAULT_KEY_TYPE,
    allow_long_validity: bool = False,
    include_common_name_in_sans: bool = True,
    allow_dn_special_chars: bool = False,
    ocsp_url: str | None = None,
) -> tuple[bytes, bytes]:
    """Generate a server (SERVER_AUTH) certificate signed by the given CA.

    ``san_entries`` must contain at least one DNS name or IP address; entries are
    normalized (see :func:`tiny_pki.names.normalize_san_entries`). Clients ignore
    the CN, so when ``common_name`` is itself a valid host/IP that is missing from
    ``san_entries`` it is appended (with a ``TinyPkiWarning``) unless
    ``include_common_name_in_sans=False``. RFC 4514 special characters in the CN
    are refused unless ``allow_dn_special_chars=True``, as for client certificates.
    ``key_type`` / ``key_size`` work as for :func:`generate_client_certificate`.

    Raises:
        TinyPkiError: If a name, SAN entry, or key parameter is invalid, ``validity_days`` exceeds
            ``MAX_SERVER_VALIDITY_DAYS`` without ``allow_long_validity=True``, or the
            certificate would outlive the CA.

    Warns:
        TinyPkiWarning: When the CN is added to the SANs, or an override exceeds
            ``APPLE_MAX_SERVER_VALIDITY_DAYS`` (Apple platforms reject it). Warnings
            are emitted only after the certificate is issued, never for a rejection.
    """
    common_name = normalize_subject_attribute(common_name, "common_name", max_length=MAX_COMMON_NAME_LENGTH)
    if not allow_dn_special_chars:
        _require_plain_common_name(common_name)
    rsa_key_size = require_key_params(key_type, key_size, default_size=DEFAULT_LEAF_KEY_SIZE)
    _require_validity_days(validity_days)
    ocsp_url = _ocsp_url(ocsp_url)
    pending_warnings: list[str] = []
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    sans = _server_sans(
        ca_cert,
        common_name,
        san_entries,
        include_common_name_in_sans=include_common_name_in_sans,
        warn=pending_warnings,
    )

    ca_key = load_ca_private_key(ca_cert, ca_key_pem)
    org = _leaf_organization(ca_cert, organization_name)
    _enforce_name_constraints(ca_cert, common_name=common_name, sans=sans)
    not_before, not_after = _leaf_validity_window(
        ca_cert, validity_days, kind="server", allow_long_validity=allow_long_validity, warn=pending_warnings
    )
    server_key = generate_private_key(rsa_key_size)
    cert = _server_certificate(
        ca_cert,
        ca_key,
        server_key.public_key(),
        common_name=common_name,
        organization_name=org,
        sans=sans,
        not_before=not_before,
        not_after=not_after,
        ocsp_url=ocsp_url,
    )
    _emit_warnings(pending_warnings)
    return _pem_pair(cert, server_key)


def sign_server_csr(
    ca_cert_pem: bytes,
    ca_key_pem: bytes,
    csr_pem: bytes,
    common_name: str,
    san_entries: list[str],
    *,
    organization_name: str | None = None,
    validity_days: int = DEFAULT_SERVER_VALIDITY_DAYS,
    allow_long_validity: bool = False,
    include_common_name_in_sans: bool = True,
    include_csr_sans: bool = False,
    allow_dn_special_chars: bool = False,
    ocsp_url: str | None = None,
) -> bytes:
    """Sign a server's certificate signing request as a server (SERVER_AUTH) certificate.

    The private key stays on the server that generated the CSR; only its public
    key is taken from ``csr_pem`` (PEM or DER). Everything else comes from the CA
    side, exactly as in :func:`generate_server_certificate`: ``common_name``, the
    SANs, the organization, the validity window, and the extensions.

    The SANs are ``san_entries`` plus the CN (``include_common_name_in_sans``, as
    for :func:`generate_server_certificate`). The DNS names and IP addresses the
    CSR requests are added only with ``include_csr_sans=True``; otherwise they
    are ignored with a warning, so a CSR cannot extend the names a certificate
    covers without the operator's say-so. Requested SANs of other types (URI,
    email, otherName, ...) are always ignored with a warning, since server
    certificates carry only DNS and IP SANs. Every other requested extension, such
    as ``BasicConstraints(ca=True)`` or a client EKU, is ignored.

    The CSR must pass the same policy as :func:`sign_client_csr`.

    Returns:
        The certificate in PEM format.

    Raises:
        TinyPkiError: If the CSR is malformed or fails that policy, a SAN (including
            an accepted CSR SAN) is invalid or outside the CA's name constraints, or
            for any reason :func:`generate_server_certificate` would refuse the name
            or validity.

    Warns:
        TinyPkiWarning: When the CSR's subject CN differs from ``common_name``, it
            requests SANs that are not included, or it requests other extensions;
            all are ignored. The CN-in-SAN and validity warnings of
            :func:`generate_server_certificate` apply too. Warnings are emitted only
            after the certificate is issued, never for a rejection.
    """
    common_name = normalize_subject_attribute(common_name, "common_name", max_length=MAX_COMMON_NAME_LENGTH)
    if not allow_dn_special_chars:
        _require_plain_common_name(common_name)
    _require_validity_days(validity_days)
    ocsp_url = _ocsp_url(ocsp_url)
    csr = load_csr(csr_pem)
    public_key = require_signable_public_key(csr)

    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    csr_sans = requested_sans(csr)
    pending_warnings = _ignored_csr_request_warnings(
        csr, common_name, profile="server", handled=frozenset({"SubjectAlternativeName"})
    )
    sans = _server_sans(
        ca_cert,
        common_name,
        [*san_entries, *csr_sans] if include_csr_sans else san_entries,
        include_common_name_in_sans=include_common_name_in_sans,
        warn=pending_warnings,
    )
    if not include_csr_sans:
        ignored = [san for san in csr_sans if _normalized_or_raw(san) not in sans]
        if ignored:
            pending_warnings.append(
                f"Ignored the SANs the CSR requests ({', '.join(ignored)}); the certificate covers "
                f"{', '.join(sans)}. Include them explicitly or with include_csr_sans=True"
            )
    unsupported = unsupported_requested_sans(csr)
    if unsupported:
        pending_warnings.append(
            f"Ignored the CSR's requested SANs that are not DNS names or IP addresses ({', '.join(unsupported)}); "
            "server certificates carry only DNS and IP SANs"
        )

    ca_key = load_ca_private_key(ca_cert, ca_key_pem)
    org = _leaf_organization(ca_cert, organization_name)
    _enforce_name_constraints(ca_cert, common_name=common_name, sans=sans)
    not_before, not_after = _leaf_validity_window(
        ca_cert, validity_days, kind="server", allow_long_validity=allow_long_validity, warn=pending_warnings
    )
    cert = _server_certificate(
        ca_cert,
        ca_key,
        public_key,
        common_name=common_name,
        organization_name=org,
        sans=sans,
        not_before=not_before,
        not_after=not_after,
        ocsp_url=ocsp_url,
    )
    _emit_warnings(pending_warnings)
    return cert.public_bytes(serialization.Encoding.PEM)


def generate_intermediate_ca_certificate(
    issuer_cert_pem: bytes,
    issuer_key_pem: bytes,
    common_name: str,
    *,
    organization_name: str | None = None,
    validity_days: int = DEFAULT_INTERMEDIATE_VALIDITY_DAYS,
    key_size: int | None = None,
    key_type: KeyType = DEFAULT_KEY_TYPE,
    permitted_subtrees: list[str] | None = None,
) -> tuple[bytes, bytes]:
    """Generate an intermediate CA certificate and key, signed by a root created with ``path_length=1``.

    The intermediate signs leaves only (``BasicConstraints(ca=True, path_length=0)``,
    ``keyCertSign`` + ``cRLSign``), so every leaf-issuing function accepts it as
    ``ca_cert_pem`` / ``ca_key_pem``, and relying parties that trust the root
    accept its leaves once they are given the chain. It inherits the issuer's
    Name Constraints; ``permitted_subtrees`` (same syntax as for
    :func:`generate_ca_certificate`) narrows them and must lie within the
    issuer's. ``organization_name=None`` reuses the issuer's O, and ``key_type`` /
    ``key_size`` work as for the root (RSA default ``DEFAULT_CA_KEY_SIZE``).

    Returns:
        Tuple of ``(certificate_pem, private_key_pem)``.

    Raises:
        TinyPkiError: If the issuer cannot sign CA certificates (``path_length=0``),
            a name or key parameter is invalid, a permitted subtree is outside the
            issuer's, or the certificate would outlive the issuer.
    """
    common_name = normalize_subject_attribute(common_name, "common_name", max_length=MAX_COMMON_NAME_LENGTH)
    rsa_key_size = require_key_params(key_type, key_size, default_size=DEFAULT_CA_KEY_SIZE)
    _require_validity_days(validity_days)
    issuer_cert = x509.load_pem_x509_certificate(issuer_cert_pem)
    _require_can_sign_intermediate(issuer_cert)
    constraints = _intermediate_name_constraints(issuer_cert, permitted_subtrees)
    issuer_key = load_ca_private_key(issuer_cert, issuer_key_pem)
    org = _leaf_organization(issuer_cert, organization_name)
    not_before, not_after = _intermediate_validity_window(issuer_cert, validity_days)
    key = generate_private_key(rsa_key_size)
    cert = _intermediate_certificate(
        issuer_cert,
        issuer_key,
        key.public_key(),
        common_name=common_name,
        organization_name=org,
        name_constraints=constraints,
        not_before=not_before,
        not_after=not_after,
    )
    return _pem_pair(cert, key)


def sign_intermediate_csr(
    issuer_cert_pem: bytes,
    issuer_key_pem: bytes,
    csr_pem: bytes,
    common_name: str,
    *,
    organization_name: str | None = None,
    validity_days: int = DEFAULT_INTERMEDIATE_VALIDITY_DAYS,
    permitted_subtrees: list[str] | None = None,
) -> bytes:
    """Sign an intermediate CA's certificate signing request, for a CA whose key lives elsewhere.

    Use it when the intermediate runs outside this process: OpenBao's
    ``pki/intermediate/generate/internal``, or a tiny-pki store on another host.
    Only the CSR's public key is used; the name, validity, constraints and
    extensions are exactly those of :func:`generate_intermediate_ca_certificate`,
    and the CSR must pass the same policy as :func:`sign_client_csr`.

    Returns:
        The certificate in PEM format.

    Raises:
        TinyPkiError: If the CSR is malformed or fails that policy, or for any
            reason :func:`generate_intermediate_ca_certificate` would refuse.

    Warns:
        TinyPkiWarning: When the CSR's subject CN differs from ``common_name``, or
            it requests extensions (its own ``BasicConstraints`` included); all are
            ignored. Warnings are emitted only after the certificate is issued.
    """
    common_name = normalize_subject_attribute(common_name, "common_name", max_length=MAX_COMMON_NAME_LENGTH)
    _require_validity_days(validity_days)
    csr = load_csr(csr_pem)
    public_key = require_signable_public_key(csr)
    issuer_cert = x509.load_pem_x509_certificate(issuer_cert_pem)
    _require_can_sign_intermediate(issuer_cert)
    constraints = _intermediate_name_constraints(issuer_cert, permitted_subtrees)
    issuer_key = load_ca_private_key(issuer_cert, issuer_key_pem)
    org = _leaf_organization(issuer_cert, organization_name)
    pending_warnings = _ignored_csr_request_warnings(csr, common_name, profile="intermediate CA")
    not_before, not_after = _intermediate_validity_window(issuer_cert, validity_days)
    cert = _intermediate_certificate(
        issuer_cert,
        issuer_key,
        public_key,
        common_name=common_name,
        organization_name=org,
        name_constraints=constraints,
        not_before=not_before,
        not_after=not_after,
    )
    _emit_warnings(pending_warnings)
    return cert.public_bytes(serialization.Encoding.PEM)


def max_leaf_validity_days(
    ca_cert_pem: bytes,
    *,
    kind: Literal["client", "server"] = "server",
    allow_long_validity: bool = False,
) -> int:
    """Return the largest ``validity_days`` that issuing a ``kind`` leaf under this CA accepts now.

    Mirrors issuance: the leaf's window is backdated by ``CLOCK_SKEW_BACKDATE`` and
    must end by the CA's ``notAfter``, and unless ``allow_long_validity`` it is also
    capped at ``MAX_SERVER_VALIDITY_DAYS`` / ``MAX_CLIENT_VALIDITY_DAYS``. Returns
    ``0`` once the CA cannot sign any leaf (it has expired or has less than a day
    left). The answer is for the current time and shrinks as the CA ages, so use
    it to clamp UI choices, not as a value to cache.

    Raises:
        TinyPkiError: If ``kind`` is not ``"client"`` or ``"server"``.
    """
    if kind not in ("client", "server"):
        raise TinyPkiError(f"Expected kind 'client' or 'server', got {kind!r}")
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    not_before, _ = _validity_window(0)
    remaining = max((ca_cert.not_valid_after_utc - not_before).days, 0)
    if allow_long_validity:
        return remaining
    return min(remaining, MAX_SERVER_VALIDITY_DAYS if kind == "server" else MAX_CLIENT_VALIDITY_DAYS)


def require_name_constraints_within(ca_cert: x509.Certificate, ancestor: x509.Certificate) -> None:
    """Refuse a CA whose own Name Constraints allow a name that ``ancestor``'s forbid.

    Issuance and ``check`` enforce only the issuing CA's constraints, so they match
    what relying parties enforce for the whole chain only when the issuing CA
    carries constraints at least as narrow as every CA above it (intermediates
    tiny-pki signs always do). For each name type ``ancestor`` permits, the CA
    must permit that type only within it; each subtree ``ancestor`` excludes must
    be excluded by the CA too, or lie outside everything the CA permits of that type.

    Raises:
        TinyPkiError: The CA's constraints are broader than ``ancestor``'s.
    """
    outer = _name_constraints(ancestor)
    if outer is None:
        return
    inner = _name_constraints(ca_cert)
    inner_permitted = list(inner.permitted_subtrees or []) if inner else []
    inner_excluded = list(inner.excluded_subtrees or []) if inner else []
    label, ancestor_label = ca_cert.subject.rfc4514_string(), ancestor.subject.rfc4514_string()
    outer_permitted = list(outer.permitted_subtrees or [])
    for name_type in {type(subtree) for subtree in outer_permitted}:
        allowed = [subtree for subtree in outer_permitted if isinstance(subtree, name_type)]
        own = [subtree for subtree in inner_permitted if isinstance(subtree, name_type)]
        if not own or not all(any(_subtree_within(s, a) for a in allowed) for s in own):
            raise TinyPkiError(
                f"Expected {label} to permit only names within {ancestor_label}'s permitted "
                f"{[str(a.value) for a in allowed]}, got {[str(s.value) for s in own] or 'any'}; "
                "relying parties would reject leaves this store issues outside them"
            )
    for excluded in outer.excluded_subtrees or []:
        if any(_subtree_within(excluded, own) for own in inner_excluded):
            continue
        same_type = [s for s in inner_permitted if isinstance(s, type(excluded))]
        if same_type and not any(_subtree_within(s, excluded) or _subtree_within(excluded, s) for s in same_type):
            continue
        raise TinyPkiError(
            f"Expected {label} to exclude {str(excluded.value)!r} like {ancestor_label} does; "
            "relying parties would reject leaves this store issues there"
        )


def _name_constraints(cert: x509.Certificate) -> x509.NameConstraints | None:
    try:
        return cert.extensions.get_extension_for_class(x509.NameConstraints).value
    except x509.ExtensionNotFound:
        return None


_CN_DNS_ID = re.compile(r"^[a-z0-9_.-]+$")
# RFC 4514 section 2.4 characters that must be escaped in a DN string (backslash is refused elsewhere).
_DN_SPECIAL_CHARS = frozenset(',+="<>;')


def _address_in(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
    *,
    unmap: bool = False,
) -> bool:
    """Membership test; ``unmap`` also treats IPv4-mapped IPv6 (``::ffff:a.b.c.d``) as the IPv4 address.

    OpenSSL compares constraints within one address family, so permitted checks
    stay literal (a mapped form is not admitted by an IPv4 subtree), while
    excluded checks unmap because clients that normalize addresses would treat
    ``::ffff:10.1.2.3`` as the excluded ``10.1.2.3``.
    """
    addresses = [address]
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [network]
    if unmap:
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            addresses.append(address.ipv4_mapped)
        mapped_base = network.network_address.ipv4_mapped if isinstance(network, ipaddress.IPv6Network) else None
        if mapped_base is not None and network.prefixlen >= 96:
            networks.append(ipaddress.IPv4Network((mapped_base, network.prefixlen - 96)))
    return any(
        a.version == n.version and int(a) & int(n.netmask) == int(n.network_address)
        for a in addresses
        for n in networks
    )


def _client_certificate(
    ca_cert: x509.Certificate,
    ca_key: PrivateKey,
    public_key: PublicKey,
    *,
    common_name: str,
    organization_name: str,
    not_before: datetime,
    not_after: datetime,
    ocsp_url: str | None,
    uri_san: str | None,
) -> x509.Certificate:
    """Build and sign the client leaf profile shared by generated and CSR-issued certificates."""
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        ]
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=isinstance(public_key, rsa.RSAPublicKey),
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
    )
    if uri_san is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri_san)]), critical=False
        )
    return _with_ocsp_url(builder, ocsp_url).sign(ca_key, hashes.SHA256())


def _cn_dns_id(common_name: str) -> str | None:
    """Return the CN as OpenSSL's name-constraint check sees it, or ``None`` if it skips it.

    With no DNS SAN, OpenSSL checks a dotted CN made of letters, digits, ``-``,
    ``_`` and ``.`` (IP literals included) against the DNS constraints.
    """
    text = common_name.strip().lower().removesuffix(".")
    if "." not in text:
        return None
    try:
        return normalize_dns_name(text)
    except ValueError:
        return text if _CN_DNS_ID.fullmatch(text) else None


def _uri_host_within(host: str, root: str) -> bool:
    """Match like OpenSSL's URI constraint: ``.example.home`` covers hosts under it, ``example.home`` only itself."""
    root = root.lower()
    if root.startswith("."):
        return host.endswith(root)
    return host == root


def _dns_within(host: str, root: str) -> bool:
    """Match like OpenSSL: ``.example.com`` covers subdomains only, ``example.com`` also the apex."""
    root = root.lower()
    if root.startswith("."):
        return host.endswith(root)
    return host == root or host.endswith("." + root)


def _emit_warnings(messages: list[str]) -> None:
    """Emit held-back ``TinyPkiWarning``s, attributed to the public API's caller."""
    for message in messages:
        warnings.warn(message, TinyPkiWarning, stacklevel=3)


def _ignored_csr_request_warnings(
    csr: x509.CertificateSigningRequest,
    common_name: str,
    *,
    profile: Literal["client", "intermediate CA", "server"],
    handled: frozenset[str] = frozenset(),
) -> list[str]:
    """Describe what a CSR asked for that signing ignores: a different CN, and requested extensions.

    ``handled`` names extensions the caller reports on itself (the server path's SANs).
    """
    messages: list[str] = []
    requested_cns = [str(attr.value) for attr in csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    if requested_cns and requested_cns != [common_name]:
        messages.append(
            f"Ignored the CSR's common name {', '.join(repr(cn) for cn in requested_cns)}; "
            f"the certificate is issued to {common_name!r}"
        )
    requested = [name for name in requested_extension_names(csr) if name not in handled]
    if requested:
        messages.append(
            f"Ignored the extensions the CSR requests ({', '.join(requested)}); the CA sets the {profile} profile"
        )
    return messages


def _normalized_or_raw(san: str) -> str:
    try:
        return normalize_san_entry(san)
    except TinyPkiError:
        return san


def _require_can_sign_intermediate(issuer_cert: x509.Certificate) -> None:
    try:
        constraints = issuer_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        constraints = None
    label = issuer_cert.subject.rfc4514_string()
    if constraints is None or not constraints.ca:
        raise TinyPkiError(f"Expected a CA certificate as the issuer, got {label}")
    if constraints.path_length is not None and constraints.path_length < 1:
        raise TinyPkiError(
            f"Expected an issuer that may sign CA certificates, but {label} has path_length="
            f"{constraints.path_length} and signs only leaves; create a root with path_length=1 "
            "(CLI: init --path-length 1)"
        )
    try:
        usage = issuer_cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return
    if not usage.key_cert_sign:
        raise TinyPkiError(
            f"Expected an issuer whose Key Usage allows keyCertSign, but {label} does not, so relying parties "
            "would reject any certificate it signs"
        )


def _require_plain_common_name(common_name: str) -> None:
    """Refuse RFC 4514 special characters that make a DN string look like another identity.

    Relying parties such as nginx (``$ssl_client_s_dn``) and Mosquitto match the
    escaped subject string, so ``bob,CN=alice`` ends in ``,CN=alice`` there.
    ``normalize_subject_attribute`` already strips leading and trailing spaces
    and rejects ``\\``.
    """
    if common_name.startswith("#"):
        raise TinyPkiError(
            f"Expected common_name without a leading '#', got {common_name!r}"
            " (pass allow_dn_special_chars=True, CLI: --allow-dn-special-chars, to allow it)"
        )
    for ch in common_name:
        if ch in _DN_SPECIAL_CHARS:
            raise TinyPkiError(
                f"Expected common_name without the DN special character {ch!r}, got {common_name!r}:"
                " it can make the subject DN look like another identity"
                " (pass allow_dn_special_chars=True, CLI: --allow-dn-special-chars, to allow it)"
            )


def _intermediate_certificate(
    issuer_cert: x509.Certificate,
    issuer_key: PrivateKey,
    public_key: PublicKey,
    *,
    common_name: str,
    organization_name: str,
    name_constraints: x509.NameConstraints | None,
    not_before: datetime,
    not_after: datetime,
) -> x509.Certificate:
    """Build and sign the intermediate CA profile shared by generated and CSR-issued intermediates."""
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        ]
    )
    builder = x509.CertificateBuilder()
    if name_constraints is not None:
        builder = builder.add_extension(name_constraints, critical=True)
    return (
        builder.subject_name(subject)
        .issuer_name(issuer_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
        .sign(issuer_key, hashes.SHA256())
    )


def _intermediate_name_constraints(
    issuer_cert: x509.Certificate, permitted_subtrees: list[str] | None
) -> x509.NameConstraints | None:
    """The issuer's Name Constraints, narrowed to ``permitted_subtrees`` when given.

    Relying parties enforce every constraint in the chain anyway; copying them
    into the intermediate lets issuance refuse out-of-bounds leaves up front.
    """
    requested = [_permitted_subtree(entry) for entry in permitted_subtrees or []]
    try:
        issuer_constraints = issuer_cert.extensions.get_extension_for_class(x509.NameConstraints).value
    except x509.ExtensionNotFound:
        issuer_constraints = None
    issuer_permitted = list(issuer_constraints.permitted_subtrees or []) if issuer_constraints else []
    excluded = list(issuer_constraints.excluded_subtrees or []) if issuer_constraints else []
    for subtree in requested:
        if issuer_permitted and not any(_subtree_within(subtree, root) for root in issuer_permitted):
            allowed = [str(g.value) for g in issuer_permitted]
            raise TinyPkiError(
                f"Expected permitted subtrees within the issuer's permitted names {allowed}, got {str(subtree.value)!r}"
            )
    permitted = requested or issuer_permitted
    if not permitted and not excluded:
        return None
    return x509.NameConstraints(permitted_subtrees=permitted or None, excluded_subtrees=excluded or None)


def _intermediate_validity_window(issuer_cert: x509.Certificate, validity_days: int) -> tuple[datetime, datetime]:
    not_before, not_after = _validity_window(validity_days)
    issuer_not_after = issuer_cert.not_valid_after_utc
    if not_after > issuer_not_after:
        remaining_days = max((issuer_not_after - not_before).days, 0)
        raise TinyPkiError(
            f"Expected the intermediate CA to expire by its issuer's notAfter ({issuer_not_after.isoformat()}), "
            f"got validity_days={validity_days}; use validity_days <= {remaining_days} or renew the issuer"
        )
    return not_before, not_after


def _is_ip_literal(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _name_type_unconstrained(ca_cert: x509.Certificate, san: str) -> bool:
    """True when the CA has permitted subtrees but none of ``san``'s type (DNS or IP)."""
    try:
        permitted = ca_cert.extensions.get_extension_for_class(x509.NameConstraints).value.permitted_subtrees
    except x509.ExtensionNotFound:
        return False
    if not permitted:
        return False
    if _is_ip_literal(san):
        return not any(isinstance(g, x509.IPAddress) for g in permitted)
    return not any(isinstance(g, x509.DNSName) for g in permitted)


def _enforce_name_constraints(
    ca_cert: x509.Certificate, *, common_name: str, sans: list[str], uris: list[str] | None = None
) -> None:
    """Refuse leaves the CA's Name Constraints would make relying parties reject."""
    try:
        constraints = ca_cert.extensions.get_extension_for_class(x509.NameConstraints).value
    except x509.ExtensionNotFound:
        return
    dns_names: list[str] = []
    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for entry in sans:
        try:
            addresses.append(ipaddress.ip_address(entry))
        except ValueError:
            dns_names.append(entry)
    cn_dns_id = _cn_dns_id(common_name) if not dns_names else None
    if cn_dns_id is not None:
        dns_names.append(cn_dns_id)
        if _is_ip_literal(cn_dns_id):
            cn_address = ipaddress.ip_address(cn_dns_id)
            if cn_address not in addresses:
                addresses.append(cn_address)
    permitted = list(constraints.permitted_subtrees or [])
    excluded = list(constraints.excluded_subtrees or [])
    permitted_roots = [str(g.value) for g in permitted if isinstance(g, x509.DNSName)]
    excluded_roots = [str(g.value) for g in excluded if isinstance(g, x509.DNSName)]
    permitted_networks = [ipaddress.ip_network(g.value) for g in permitted if isinstance(g, x509.IPAddress)]
    excluded_networks = [ipaddress.ip_network(g.value) for g in excluded if isinstance(g, x509.IPAddress)]
    # RFC 5280 leaves a name type unconstrained when no subtree of that type is
    # listed; a device-wide private CA wants the opposite, so once any permitted
    # subtree exists, every name type used must have one.
    strict = bool(permitted)
    for name in dns_names:
        host = name.removeprefix("*.")
        # An IP-literal CN (checked as DNS by OpenSSL) is not a hostname identity.
        if strict and not permitted_roots and not _is_ip_literal(host):
            raise TinyPkiError(
                f"Expected no DNS names from a CA without a permitted DNS subtree, got {name!r}"
                " (recreate the CA with a DNS --permit, or use an IP SAN and a CN without dots)"
            )
        if permitted_roots and not any(_dns_within(host, root) for root in permitted_roots):
            raise TinyPkiError(f"Expected DNS name within the CA's permitted names {permitted_roots}, got {name!r}")
        if any(_dns_within(host, root) for root in excluded_roots):
            raise TinyPkiError(f"Expected DNS name outside the CA's excluded names {excluded_roots}, got {name!r}")
    for address in addresses:
        if strict and not permitted_networks:
            raise TinyPkiError(
                f"Expected no IP addresses from a CA without a permitted IP subtree, got {address}"
                " (recreate the CA with an IP --permit)"
            )
        if permitted_networks and not any(_address_in(address, network) for network in permitted_networks):
            permitted_text = [str(n) for n in permitted_networks]
            raise TinyPkiError(
                f"Expected IP address within the CA's permitted networks {permitted_text}, got {address}"
            )
        if any(_address_in(address, network, unmap=True) for network in excluded_networks):
            excluded_text = [str(n) for n in excluded_networks]
            raise TinyPkiError(f"Expected IP address outside the CA's excluded networks {excluded_text}, got {address}")
    permitted_hosts = [str(g.value) for g in permitted if isinstance(g, x509.UniformResourceIdentifier)]
    excluded_hosts = [str(g.value) for g in excluded if isinstance(g, x509.UniformResourceIdentifier)]
    for uri in uris or []:
        host = (urlsplit(uri).hostname or "").lower()
        if strict and not permitted_hosts:
            raise TinyPkiError(
                f"Expected no URI SANs from a CA without a permitted URI subtree, got {uri!r}"
                " (recreate the CA with --permit-uri HOST)"
            )
        if permitted_hosts and not any(_uri_host_within(host, root) for root in permitted_hosts):
            raise TinyPkiError(
                f"Expected a URI whose host is within the CA's permitted URI hosts {permitted_hosts}, got {uri!r}"
            )
        if any(_uri_host_within(host, root) for root in excluded_hosts):
            raise TinyPkiError(
                f"Expected a URI whose host is outside the CA's excluded URI hosts {excluded_hosts}, got {uri!r}"
            )


def _leaf_organization(ca_cert: x509.Certificate, organization_name: str | None) -> str:
    """Return the leaf O: explicit value, else the CA's O, else the default."""
    if organization_name is not None:
        return normalize_subject_attribute(
            organization_name, "organization_name", max_length=MAX_ORGANIZATION_NAME_LENGTH
        )
    ca_org_attrs = ca_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    return str(ca_org_attrs[0].value) if ca_org_attrs else DEFAULT_ORGANIZATION_NAME


def _leaf_validity_window(
    ca_cert: x509.Certificate,
    validity_days: int,
    *,
    kind: Literal["client", "server"],
    allow_long_validity: bool,
    warn: list[str],
) -> tuple[datetime, datetime]:
    """Return ``(not_before, not_after)`` after enforcing lifetime policy.

    Warning messages are appended to ``warn`` rather than emitted, so callers can
    hold them back until issuance is certain to succeed.
    """
    cap = MAX_SERVER_VALIDITY_DAYS if kind == "server" else MAX_CLIENT_VALIDITY_DAYS
    if validity_days > cap and not allow_long_validity:
        raise TinyPkiError(
            f"Expected validity_days <= {cap} for {kind} certificates, got {validity_days}; "
            "pass allow_long_validity=True (CLI: --allow-long-validity) to override"
        )
    if kind == "server" and validity_days > APPLE_MAX_SERVER_VALIDITY_DAYS:
        warn.append(
            f"Server certificate validity {validity_days} days exceeds "
            f"{APPLE_MAX_SERVER_VALIDITY_DAYS}; Apple platforms will reject it"
        )
    not_before, not_after = _validity_window(validity_days)
    ca_not_after = ca_cert.not_valid_after_utc
    if not_after > ca_not_after:
        remaining_days = max((ca_not_after - not_before).days, 0)
        raise TinyPkiError(
            f"Expected {kind} certificate to expire by the CA's notAfter "
            f"({ca_not_after.isoformat()}), got validity_days={validity_days}; "
            f"use validity_days <= {remaining_days} or renew the CA"
        )
    return not_before, not_after


def _ocsp_url(url: str | None) -> str | None:
    return None if url is None else normalize_http_url(url, "ocsp_url")


def _pem_pair(cert: x509.Certificate, key: PrivateKey) -> tuple[bytes, bytes]:
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def _permitted_subtree(entry: str) -> x509.GeneralName:
    text = entry.strip()
    if not text:
        raise TinyPkiError("Expected a non-empty permitted subtree")
    if text.lower().startswith(URI_SUBTREE_PREFIX):
        return _permitted_uri_subtree(text[len(URI_SUBTREE_PREFIX) :], entry)
    if "://" in text:
        raise TinyPkiError(f"Expected a DNS suffix or IP network, not a URL, got {entry!r}")
    try:
        return x509.IPAddress(ipaddress.ip_network(text, strict=True))
    except ValueError as exc:
        if "/" in text:
            raise TinyPkiError(
                f"Expected an IP network without host bits (e.g. 192.168.0.0/16), got {entry!r}"
            ) from exc
    if "*" in text:
        raise TinyPkiError(f"Expected a DNS suffix without wildcards (e.g. home), got {entry!r}")
    if text.startswith("."):
        raise TinyPkiError(
            f"Expected a DNS suffix without a leading dot, got {entry!r}: {text.lstrip('.')!r} already covers "
            "every name under it (and the name itself); subdomain-only constraints are not supported"
        )
    return x509.DNSName(normalize_dns_name(text))


def _permitted_uri_subtree(host: str, entry: str) -> x509.UniformResourceIdentifier:
    """A URI subtree: ``HOST`` permits URIs with exactly that host, ``.HOST`` any host under it (RFC 5280)."""
    text = host.strip()
    subdomains_only = text.startswith(".")
    try:
        name = normalize_dns_name(text.removeprefix("."))
    except ValueError as exc:
        raise TinyPkiError(
            f"Expected {URI_SUBTREE_PREFIX}HOST or {URI_SUBTREE_PREFIX}.HOST with a DNS host (e.g. "
            f"{URI_SUBTREE_PREFIX}example.home), got {entry!r}"
        ) from exc
    return x509.UniformResourceIdentifier(f".{name}" if subdomains_only else name)


def _require_validity_days(validity_days: int) -> None:
    if not 0 < validity_days <= MAX_VALIDITY_DAYS:
        raise TinyPkiError(f"Expected validity_days between 1 and {MAX_VALIDITY_DAYS}, got {validity_days}")


def _server_certificate(
    ca_cert: x509.Certificate,
    ca_key: PrivateKey,
    public_key: PublicKey,
    *,
    common_name: str,
    organization_name: str,
    sans: list[str],
    not_before: datetime,
    not_after: datetime,
    ocsp_url: str | None,
) -> x509.Certificate:
    """Build and sign the server leaf profile shared by generated and CSR-issued certificates."""
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        ]
    )
    san_objects: list[x509.GeneralName] = []
    for entry in sans:
        try:
            san_objects.append(x509.IPAddress(ipaddress.ip_address(entry)))
        except ValueError:
            san_objects.append(x509.DNSName(entry))
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=isinstance(public_key, rsa.RSAPublicKey),
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName(san_objects), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
    )
    return _with_ocsp_url(builder, ocsp_url).sign(ca_key, hashes.SHA256())


def _server_sans(
    ca_cert: x509.Certificate,
    common_name: str,
    san_entries: list[str],
    *,
    include_common_name_in_sans: bool,
    warn: list[str],
) -> list[str]:
    """Normalize ``san_entries`` and add a host-like CN to them, as the server profile does."""
    sans = normalize_san_entries(san_entries)
    cn_san = common_name_as_san(common_name)
    if include_common_name_in_sans and cn_san is not None and cn_san not in sans:
        if _name_type_unconstrained(ca_cert, cn_san):
            warn.append(f"Did not add common_name {common_name!r} to the SANs: the CA has no permitted subtree for it")
        else:
            sans.append(cn_san)
            warn.append(f"Added common_name {common_name!r} to the SANs as {cn_san!r} (TLS clients ignore the CN)")
    return sans


def _subtree_within(subtree: x509.GeneralName, root: x509.GeneralName) -> bool:
    if isinstance(subtree, x509.DNSName) and isinstance(root, x509.DNSName):
        return _dns_within(subtree.value, root.value)
    if isinstance(subtree, x509.UniformResourceIdentifier) and isinstance(root, x509.UniformResourceIdentifier):
        inner, outer = subtree.value.lower(), root.value.lower()
        return inner == outer or (outer.startswith(".") and inner.endswith(outer))
    if isinstance(subtree, x509.IPAddress) and isinstance(root, x509.IPAddress):
        inner, outer = subtree.value, root.value
        if isinstance(inner, ipaddress.IPv4Network) and isinstance(outer, ipaddress.IPv4Network):
            return inner.subnet_of(outer)
        if isinstance(inner, ipaddress.IPv6Network) and isinstance(outer, ipaddress.IPv6Network):
            return inner.subnet_of(outer)
    return False


def _validity_window(validity_days: int) -> tuple[datetime, datetime]:
    """Backdate the whole window so the encoded period is exactly ``validity_days``."""
    not_before = datetime.now(UTC) - CLOCK_SKEW_BACKDATE
    return not_before, not_before + timedelta(days=validity_days)


def _with_ocsp_url(builder: x509.CertificateBuilder, ocsp_url: str | None) -> x509.CertificateBuilder:
    """Point relying parties at the OCSP responder (Authority Information Access) when one is configured."""
    if ocsp_url is None:
        return builder
    access = x509.AccessDescription(AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(ocsp_url))
    return builder.add_extension(x509.AuthorityInformationAccess([access]), critical=False)
