"""Issue CA, server, and client certificates (PEM bytes in / out).

Extracted and generalized from ``the-hcma/my-tracks`` ``app/pki.py`` (MIT).
"""

from __future__ import annotations

import ipaddress
import re
import warnings
from datetime import UTC, datetime, timedelta
from typing import Literal

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tiny_pki._rsa import load_rsa_private_key
from tiny_pki.constants import (
    ALLOWED_KEY_SIZES,
    APPLE_MAX_SERVER_VALIDITY_DAYS,
    CLOCK_SKEW_BACKDATE,
    DEFAULT_CA_KEY_SIZE,
    DEFAULT_CA_VALIDITY_DAYS,
    DEFAULT_CLIENT_VALIDITY_DAYS,
    DEFAULT_LEAF_KEY_SIZE,
    DEFAULT_ORGANIZATION_NAME,
    DEFAULT_SERVER_VALIDITY_DAYS,
    MAX_CLIENT_VALIDITY_DAYS,
    MAX_SERVER_VALIDITY_DAYS,
)
from tiny_pki.errors import TinyPkiError, TinyPkiWarning
from tiny_pki.names import (
    MAX_COMMON_NAME_LENGTH,
    MAX_ORGANIZATION_NAME_LENGTH,
    common_name_as_san,
    normalize_dns_name,
    normalize_san_entries,
    normalize_subject_attribute,
)


def generate_ca_certificate(
    common_name: str = "Private CA",
    *,
    organization_name: str = DEFAULT_ORGANIZATION_NAME,
    validity_days: int = DEFAULT_CA_VALIDITY_DAYS,
    key_size: int = DEFAULT_CA_KEY_SIZE,
    permitted_subtrees: list[str] | None = None,
) -> tuple[bytes, bytes]:
    """Generate a self-signed CA certificate and private key.

    The CA may only sign leaves (``BasicConstraints(path_length=0)``).
    ``permitted_subtrees`` optionally restricts it with a critical Name Constraints
    extension: DNS suffixes (``"home"`` permits ``home`` and ``*.home``) and IP
    networks (``"192.168.0.0/16"``; a bare IP means a single host). RFC 5280
    constraints only apply to the name types listed, so include IP ranges too if
    leaves will carry IP SANs.

    The validity window is backdated by ``CLOCK_SKEW_BACKDATE`` so relying parties
    with slightly slow clocks accept the certificate immediately; the encoded
    period stays exactly ``validity_days``.

    Returns:
        Tuple of ``(certificate_pem, private_key_pem)``.

    Raises:
        TinyPkiError: If ``key_size`` is not in ``ALLOWED_KEY_SIZES``, a name is
            empty, too long, or contains control characters, or a permitted subtree
            is invalid.
    """
    common_name = normalize_subject_attribute(common_name, "common_name", max_length=MAX_COMMON_NAME_LENGTH)
    organization_name = normalize_subject_attribute(
        organization_name, "organization_name", max_length=MAX_ORGANIZATION_NAME_LENGTH
    )
    _require_key_size(key_size)
    _require_validity_days(validity_days)
    subtrees = [_permitted_subtree(entry) for entry in permitted_subtrees or []]

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
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
    key_size: int = DEFAULT_LEAF_KEY_SIZE,
    allow_long_validity: bool = False,
) -> tuple[bytes, bytes]:
    """Generate a client (CLIENT_AUTH) certificate signed by the given CA.

    ``common_name`` is the identity embedded in the CN (person, device, or service).

    When ``organization_name`` is omitted, the CA certificate's O is reused, falling
    back to ``DEFAULT_ORGANIZATION_NAME`` if the CA has no O attribute.

    Raises:
        TinyPkiError: If a name is invalid, ``validity_days`` exceeds
            ``MAX_CLIENT_VALIDITY_DAYS`` without ``allow_long_validity=True``, or the
            certificate would outlive the CA.
    """
    common_name = normalize_subject_attribute(common_name, "common_name", max_length=MAX_COMMON_NAME_LENGTH)
    _require_key_size(key_size)
    _require_validity_days(validity_days)

    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key = load_rsa_private_key(ca_key_pem)
    org = _leaf_organization(ca_cert, organization_name)
    _enforce_name_constraints(ca_cert, common_name=common_name, sans=[])
    pending_warnings: list[str] = []
    not_before, not_after = _leaf_validity_window(
        ca_cert, validity_days, kind="client", allow_long_validity=allow_long_validity, warn=pending_warnings
    )
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
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
            x509.SubjectKeyIdentifier.from_public_key(client_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    _emit_warnings(pending_warnings)
    return _pem_pair(cert, client_key)


def generate_server_certificate(
    ca_cert_pem: bytes,
    ca_key_pem: bytes,
    common_name: str,
    san_entries: list[str],
    *,
    organization_name: str | None = None,
    validity_days: int = DEFAULT_SERVER_VALIDITY_DAYS,
    key_size: int = DEFAULT_LEAF_KEY_SIZE,
    allow_long_validity: bool = False,
    include_common_name_in_sans: bool = True,
) -> tuple[bytes, bytes]:
    """Generate a server (SERVER_AUTH) certificate signed by the given CA.

    ``san_entries`` must contain at least one DNS name or IP address; entries are
    normalized (see :func:`tiny_pki.names.normalize_san_entries`). Clients ignore
    the CN, so when ``common_name`` is itself a valid host/IP that is missing from
    ``san_entries`` it is appended (with a ``TinyPkiWarning``) unless
    ``include_common_name_in_sans=False``.

    Raises:
        TinyPkiError: If a name or SAN entry is invalid, ``validity_days`` exceeds
            ``MAX_SERVER_VALIDITY_DAYS`` without ``allow_long_validity=True``, or the
            certificate would outlive the CA.

    Warns:
        TinyPkiWarning: When the CN is added to the SANs, or an override exceeds
            ``APPLE_MAX_SERVER_VALIDITY_DAYS`` (Apple platforms reject it). Warnings
            are emitted only after the certificate is issued, never for a rejection.
    """
    common_name = normalize_subject_attribute(common_name, "common_name", max_length=MAX_COMMON_NAME_LENGTH)
    _require_key_size(key_size)
    _require_validity_days(validity_days)
    sans = normalize_san_entries(san_entries)
    pending_warnings: list[str] = []
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    cn_san = common_name_as_san(common_name)
    if include_common_name_in_sans and cn_san is not None and cn_san not in sans:
        if _name_type_unconstrained(ca_cert, cn_san):
            pending_warnings.append(
                f"Did not add common_name {common_name!r} to the SANs: the CA has no permitted subtree for it"
            )
        else:
            sans.append(cn_san)
            pending_warnings.append(
                f"Added common_name {common_name!r} to the SANs as {cn_san!r} (TLS clients ignore the CN)"
            )

    ca_key = load_rsa_private_key(ca_key_pem)
    org = _leaf_organization(ca_cert, organization_name)
    _enforce_name_constraints(ca_cert, common_name=common_name, sans=sans)
    not_before, not_after = _leaf_validity_window(
        ca_cert, validity_days, kind="server", allow_long_validity=allow_long_validity, warn=pending_warnings
    )
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        ]
    )
    san_objects: list[x509.GeneralName] = []
    for entry in sans:
        try:
            san_objects.append(x509.IPAddress(ipaddress.ip_address(entry)))
        except ValueError:
            san_objects.append(x509.DNSName(entry))

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
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
            x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    _emit_warnings(pending_warnings)
    return _pem_pair(cert, server_key)


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


_CN_DNS_ID = re.compile(r"^[a-z0-9_.-]+$")


def _address_in(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> bool:
    return address.version == network.version and int(address) & int(network.netmask) == int(network.network_address)


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


def _enforce_name_constraints(ca_cert: x509.Certificate, *, common_name: str, sans: list[str]) -> None:
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
        if any(_address_in(address, network) for network in excluded_networks):
            excluded_text = [str(n) for n in excluded_networks]
            raise TinyPkiError(f"Expected IP address outside the CA's excluded networks {excluded_text}, got {address}")


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


def _pem_pair(cert: x509.Certificate, key: rsa.RSAPrivateKey) -> tuple[bytes, bytes]:
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
    return x509.DNSName(normalize_dns_name(text.lstrip(".")))


def _require_key_size(key_size: int) -> None:
    if key_size not in ALLOWED_KEY_SIZES:
        raise TinyPkiError(f"Expected key_size in {ALLOWED_KEY_SIZES}, got {key_size}")


def _require_validity_days(validity_days: int) -> None:
    if validity_days <= 0:
        raise TinyPkiError(f"Expected validity_days > 0, got {validity_days}")


def _validity_window(validity_days: int) -> tuple[datetime, datetime]:
    """Backdate the whole window so the encoded period is exactly ``validity_days``."""
    not_before = datetime.now(UTC) - CLOCK_SKEW_BACKDATE
    return not_before, not_before + timedelta(days=validity_days)
