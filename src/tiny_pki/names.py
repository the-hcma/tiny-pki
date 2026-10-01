"""Subject-name and SAN validation / normalization.

Relying parties match hostnames against SANs only (RFC 6125; the CN is ignored),
so SAN entries are normalized to the exact form clients compare against:
lower-case A-label DNS names without a trailing dot, or canonical IP literals.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from urllib.parse import urlsplit

from tiny_pki.errors import TinyPkiError

MAX_COMMON_NAME_LENGTH = 64
MAX_DNS_NAME_LENGTH = 253
MAX_ORGANIZATION_NAME_LENGTH = 64


def common_name_as_san(common_name: str) -> str | None:
    """Return the normalized SAN form of ``common_name``, or ``None`` if it is not a host/IP."""
    try:
        return normalize_san_entry(common_name)
    except ValueError:
        return None


def normalize_dns_name(name: str) -> str:
    """Return ``name`` as a lower-case A-label DNS name (IDNs are punycode-encoded).

    Wildcards are allowed only as the entire leftmost label, followed by at least
    two labels (``*.lan.example``) — OpenSSL refuses to match shorter patterns.

    Raises:
        TinyPkiError: If ``name`` is not a valid DNS name.
    """
    text = name.strip()
    if text.endswith("."):
        text = text[:-1]
    if not text:
        raise TinyPkiError(f"Expected a DNS name, got {name!r}")
    if ":" in text:
        raise TinyPkiError(f"Expected a DNS name without a port, got {name!r}")
    if any(ch.isspace() for ch in text):
        raise TinyPkiError(f"Expected a DNS name without whitespace, got {name!r}")
    labels = text.split(".")
    wildcard = labels[0] == "*"
    if wildcard:
        labels = labels[1:]
        if len(labels) < 2:
            raise TinyPkiError(
                f"Expected a wildcard followed by at least two labels (e.g. *.lan.example), got {name!r}"
            )
    ascii_labels = [_to_a_label(label, name) for label in labels]
    if ascii_labels[-1].isdigit():
        raise TinyPkiError(f"Expected a DNS name whose last label is not numeric (malformed IP?), got {name!r}")
    result = ".".join(["*", *ascii_labels] if wildcard else ascii_labels)
    if len(result) > MAX_DNS_NAME_LENGTH:
        raise TinyPkiError(f"Expected a DNS name of at most {MAX_DNS_NAME_LENGTH} characters, got {len(result)}")
    return result


def normalize_http_url(url: str, field_name: str) -> str:
    """Return ``url`` stripped, requiring an ``http://`` or ``https://`` URL with a host.

    Used for URLs written into certificates (such as the OCSP responder in
    Authority Information Access), which relying parties fetch as-is.

    Raises:
        TinyPkiError: For another scheme, a missing host, or non-ASCII, whitespace
            or control characters.
    """
    text = url.strip() if url else ""
    try:
        parts = urlsplit(text)
        host = parts.hostname
    except ValueError:
        host = None
        parts = None
    if (
        parts is None
        or parts.scheme not in ("http", "https")
        or not host
        or not text.isascii()
        or any(ch.isspace() or not ch.isprintable() for ch in text)
    ):
        raise TinyPkiError(f"Expected an http:// or https:// URL with a host for {field_name}, got {url!r}")
    return text


def normalize_uri_san(uri: str) -> str:
    """Return ``uri`` stripped with a lower-case scheme, requiring an absolute URI fit for a URI SAN.

    The URI needs a scheme and a host, and may not carry user info, a query or a
    fragment. A ``spiffe://`` URI must also be a valid SPIFFE ID: a lower-case
    trust domain without a port, and a path of non-empty segments made of
    letters, digits, ``.``, ``-`` and ``_``, none of them ``.`` or ``..``.

    Raises:
        TinyPkiError: If ``uri`` breaks any of those rules.
    """
    text = uri.strip() if uri else ""
    expected = "an absolute URI with a scheme and a host, without user info, query or fragment"
    try:
        parts = urlsplit(text)
        host = parts.hostname
    except ValueError:
        parts, host = None, None
    if (
        parts is None
        or not host
        or not _URI_SCHEME.fullmatch(parts.scheme)
        or "@" in parts.netloc
        or "?" in text
        or "#" in text
        or len(text) > _MAX_URI_LENGTH
        or not text.isascii()
        or any(ch.isspace() or not ch.isprintable() for ch in text)
    ):
        raise TinyPkiError(f"Expected {expected} (at most {_MAX_URI_LENGTH} characters), got {uri!r}")
    scheme = parts.scheme.lower()
    if scheme == "spiffe":
        segments = parts.path.split("/")[1:]
        if (
            not _SPIFFE_TRUST_DOMAIN.fullmatch(parts.netloc)
            or not parts.path.startswith("/")
            or not all(_SPIFFE_SEGMENT.fullmatch(segment) and segment not in (".", "..") for segment in segments)
        ):
            raise TinyPkiError(
                "Expected a SPIFFE ID such as spiffe://example.home/device/phone-1 (lower-case trust domain without "
                f"a port; non-empty path segments of letters, digits, '.', '-' and '_', none '.' or '..'), got {uri!r}"
            )
    return scheme + text[len(parts.scheme) :]


def normalize_san_entries(entries: list[str]) -> list[str]:
    """Normalize every SAN entry and drop duplicates, preserving first-seen order.

    Raises:
        TinyPkiError: If ``entries`` is empty or any entry is invalid.
    """
    if not entries:
        raise TinyPkiError("Expected at least one SAN entry, got empty list")
    result: list[str] = []
    for entry in entries:
        normalized = normalize_san_entry(entry)
        if normalized not in result:
            result.append(normalized)
    return result


def normalize_san_entry(entry: str) -> str:
    """Return a canonical IP literal or DNS name for one SAN entry.

    Raises:
        TinyPkiError: For URLs, ``host:port``, CIDR ranges, scoped IPv6 addresses, or
            invalid DNS names.
    """
    text = entry.strip()
    if not text:
        raise TinyPkiError(f"Expected a non-empty SAN entry, got {entry!r}")
    if "://" in text:
        raise TinyPkiError(f"Expected a bare DNS name or IP address, not a URL, got {entry!r}")
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        pass
    else:
        if isinstance(address, ipaddress.IPv6Address) and address.scope_id:
            raise TinyPkiError(f"Expected an IPv6 address without a zone ID, got {entry!r}")
        return str(address)
    if "/" in text:
        raise TinyPkiError(f"Expected a single IP address, not a CIDR range, got {entry!r}")
    return normalize_dns_name(text)


def normalize_subject_attribute(value: str, field_name: str, *, max_length: int) -> str:
    """Strip ``value`` and reject empty, over-long, control-character, or path-separator input.

    Path separators are rejected because a subject attribute (typically the
    common name) can end up as a filename component — e.g. the CLI's
    ``export pem`` defaults its output path to ``f"{common_name}.pem"`` — and
    ``/`` or ``\\`` there would let a crafted name write outside the intended
    directory.

    Raises:
        TinyPkiError: With the field name and the offending value.
    """
    text = value.strip() if value else ""
    if not text:
        raise TinyPkiError(f"Expected a non-empty {field_name}")
    if len(text) > max_length:
        raise TinyPkiError(f"Expected {field_name} of at most {max_length} characters, got {len(text)}")
    for ch in text:
        if unicodedata.category(ch) in _FORBIDDEN_CATEGORIES:
            raise TinyPkiError(f"Expected {field_name} without control or format characters, got {text!r}")
    if "/" in text or "\\" in text:
        raise TinyPkiError(f"Expected {field_name} without path separators, got {text!r}")
    return text


_FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Co", "Cs", "Zl", "Zp"})
_MAX_URI_LENGTH = 2048
_SPIFFE_SEGMENT = re.compile(r"^[A-Za-z0-9._-]+$")
_SPIFFE_TRUST_DOMAIN = re.compile(r"^[a-z0-9._-]+$")
_URI_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*$")
_LDH_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _to_a_label(label: str, original: str) -> str:
    if not label:
        raise TinyPkiError(f"Expected a DNS name without empty labels, got {original!r}")
    if label == "*":
        raise TinyPkiError(f"Expected a wildcard only as the entire leftmost label, got {original!r}")
    if label.isascii():
        ascii_label = label.lower()
    else:
        try:
            ascii_label = label.encode("idna").decode("ascii").lower()
            round_trip = ascii_label.encode("ascii").decode("idna")
        except UnicodeError as exc:
            raise TinyPkiError(f"Expected a valid internationalized DNS label, got {label!r} in {original!r}") from exc
        if round_trip != unicodedata.normalize("NFC", label).lower():
            # IDNA2003 nameprep maps e.g. "ß" to "ss", naming a different domain
            # than the IDNA2008 A-label TLS clients compute.
            raise TinyPkiError(
                f"Expected an internationalized label that encodes unambiguously, got {label!r} "
                f"(IDNA2003 maps it to {ascii_label!r}) in {original!r}; pass the xn-- A-label instead"
            )
    if not _LDH_LABEL.fullmatch(ascii_label):
        raise TinyPkiError(
            f"Expected DNS labels of letters, digits, and inner hyphens (max 63 chars), got {label!r} in {original!r}"
        )
    return ascii_label
