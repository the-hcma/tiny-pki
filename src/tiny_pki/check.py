"""Expiry and validity checks for certificates and CRLs (PEM in, status out).

A check answers "is this artifact usable now, and will it still be usable at the
cutoff?". The cutoff is ``now + within``, ``by``, or the earlier of the two;
with neither, it is ``now + default_warning_window(...)``.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Literal

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tiny_pki.constants import MAX_CA_WARNING_DAYS, MAX_LEAF_WARNING_DAYS
from tiny_pki.errors import TinyPkiError

type CertificateKind = Literal["ca", "client", "crl", "server", "unknown"]


@dataclass(frozen=True)
class CertificateStatus:
    """Outcome of :func:`check_certificate` or :func:`check_crl`.

    ``not_after`` is the effective end of validity: for a leaf checked against
    its CA, the earlier of the leaf's and the CA's ``notAfter``. The default
    warning window still follows the leaf's own lifetime (its renewal cadence). For a CRL,
    ``not_before`` / ``not_after`` are ``lastUpdate`` / ``nextUpdate``.
    """

    kind: CertificateKind
    subject: str
    issuer: str
    serial_number: int | None
    not_before: datetime
    not_after: datetime | None
    cutoff: datetime
    days_remaining: int | None
    status: Status
    reasons: tuple[str, ...]


class Status(StrEnum):
    """Check outcome, declared from least to most severe."""

    OK = "ok"
    EXPIRING = "expiring"
    NOT_YET_VALID = "not_yet_valid"
    EXPIRED = "expired"
    REVOKED = "revoked"
    UNTRUSTED = "untrusted"

    @property
    def severity(self) -> int:
        """Position in the declaration order; higher is worse."""
        return list(Status).index(self)


def check_certificate(
    cert_pem: bytes,
    *,
    now: datetime | None = None,
    within: timedelta | None = None,
    by: datetime | None = None,
    ca_cert_pem: bytes | None = None,
    crl_pem: bytes | None = None,
) -> CertificateStatus:
    """Check a certificate's validity now and at the cutoff.

    Args:
        cert_pem: The certificate to check.
        now: Evaluation time (timezone-aware); defaults to the current time.
        within: Flag certificates that expire within this window of ``now``.
        by: Flag certificates that expire on or before this instant.
        ca_cert_pem: The issuing CA. When given, a bad issuer or signature makes
            the result ``UNTRUSTED``, and a CA that expires first shortens the
            effective validity.
        crl_pem: A CRL from the same CA; a listed serial makes the result
            ``REVOKED``. Requires ``ca_cert_pem`` so the CRL's signature can be
            verified.

    Raises:
        TinyPkiError: On naive datetimes, a negative ``within``, a ``ca_cert_pem``
            that is not a CA certificate, a CRL without a CA, or a CRL not signed
            by the given CA.
    """
    now = _require_aware(now or datetime.now(UTC), "now")
    cert = x509.load_pem_x509_certificate(cert_pem)
    kind = _certificate_kind(cert)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    window = default_warning_window(kind, not_after - not_before)
    reasons: list[tuple[Status, str]] = []

    if crl_pem is not None and ca_cert_pem is None:
        raise TinyPkiError("Expected ca_cert_pem with crl_pem so the CRL signature can be verified")
    if ca_cert_pem is not None:
        ca_cert = _load_ca(ca_cert_pem)
        if not _is_issued_by(cert, ca_cert):
            reasons.append((Status.UNTRUSTED, f"not issued by {_name_label(ca_cert.subject)}"))
        elif ca_cert.not_valid_after_utc < not_after:
            not_after = ca_cert.not_valid_after_utc
            reasons.append((Status.OK, f"CA expires first ({not_after.isoformat()})"))
        if crl_pem is not None:
            crl = x509.load_pem_x509_crl(crl_pem)
            if not _crl_signed_by(crl, ca_cert):
                raise TinyPkiError(f"Expected a CRL signed by {_name_label(ca_cert.subject)}")
            revoked = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
            if revoked is not None:
                reasons.append((Status.REVOKED, f"revoked on {revoked.revocation_date_utc.isoformat()}"))

    cutoff = _cutoff(now, within=within, by=by, default=window)
    reasons.extend(_time_reasons(now, not_before, not_after, cutoff))
    return _result(
        kind=kind,
        subject=_name_label(cert.subject),
        issuer=_name_label(cert.issuer),
        serial_number=cert.serial_number,
        not_before=not_before,
        not_after=not_after,
        now=now,
        cutoff=cutoff,
        reasons=reasons,
    )


def check_crl(
    crl_pem: bytes,
    *,
    now: datetime | None = None,
    within: timedelta | None = None,
    by: datetime | None = None,
    ca_cert_pem: bytes | None = None,
) -> CertificateStatus:
    """Check a CRL's freshness: ``EXPIRED`` once ``nextUpdate`` passes.

    With ``ca_cert_pem``, a CRL not signed by that CA is ``UNTRUSTED``. A CRL
    without ``nextUpdate`` never goes stale and is reported as ``OK``.

    Raises:
        TinyPkiError: On naive datetimes, a negative ``within``, or a
            ``ca_cert_pem`` that is not a CA certificate.
    """
    now = _require_aware(now or datetime.now(UTC), "now")
    crl = x509.load_pem_x509_crl(crl_pem)
    reasons: list[tuple[Status, str]] = []
    if ca_cert_pem is not None:
        ca_cert = _load_ca(ca_cert_pem)
        if not _crl_signed_by(crl, ca_cert):
            reasons.append((Status.UNTRUSTED, f"not signed by {_name_label(ca_cert.subject)}"))
    not_before = crl.last_update_utc
    not_after = crl.next_update_utc
    if not_after is None:
        cutoff = _cutoff(now, within=within, by=by, default=timedelta(0))
        reasons.append((Status.OK, "no nextUpdate"))
    else:
        window = default_warning_window("crl", not_after - not_before)
        cutoff = _cutoff(now, within=within, by=by, default=window)
        reasons.extend(_time_reasons(now, not_before, not_after, cutoff))
    try:
        crl_number: int | None = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    except x509.ExtensionNotFound:
        crl_number = None
    issuer = _name_label(crl.issuer)
    return _result(
        kind="crl",
        subject=issuer,
        issuer=issuer,
        serial_number=crl_number,
        not_before=not_before,
        not_after=not_after,
        now=now,
        cutoff=cutoff,
        reasons=reasons,
    )


def default_warning_window(kind: CertificateKind, lifetime: timedelta) -> timedelta:
    """One third of ``lifetime``, capped at 180 days for a CA and 30 days for leaves.

    CRLs are not capped: their window is already short.
    """
    window = max(lifetime, timedelta(0)) / 3
    if kind == "crl":
        return window
    cap_days = MAX_CA_WARNING_DAYS if kind == "ca" else MAX_LEAF_WARNING_DAYS
    return min(window, timedelta(days=cap_days))


def worst_status(results: list[CertificateStatus]) -> Status:
    """Return the most severe status in ``results`` (``OK`` when empty)."""
    return max((r.status for r in results), key=lambda s: s.severity, default=Status.OK)


_CRL_ISSUER_KEY_TYPES = (rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)


def _certificate_kind(cert: x509.Certificate) -> CertificateKind:
    try:
        if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            return "ca"
    except x509.ExtensionNotFound:
        pass
    try:
        usages = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return "unknown"
    if ExtendedKeyUsageOID.SERVER_AUTH in usages:
        return "server"
    if ExtendedKeyUsageOID.CLIENT_AUTH in usages:
        return "client"
    return "unknown"


def _crl_signed_by(crl: x509.CertificateRevocationList, ca_cert: x509.Certificate) -> bool:
    key = ca_cert.public_key()
    if not isinstance(
        key, rsa.RSAPublicKey | ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey | ed448.Ed448PublicKey
    ):
        return False
    return crl.is_signature_valid(key)


def _cutoff(now: datetime, *, within: timedelta | None, by: datetime | None, default: timedelta) -> datetime:
    if within is not None and within < timedelta(0):
        raise TinyPkiError(f"Expected a non-negative within, got {within}")
    candidates: list[datetime] = []
    if within is not None:
        candidates.append(now + within)
    if by is not None:
        candidates.append(_require_aware(by, "by"))
    return min(candidates) if candidates else now + default


def _is_issued_by(cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    try:
        cert.verify_directly_issued_by(ca_cert)
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True


def _load_ca(ca_cert_pem: bytes) -> x509.Certificate:
    """Load a trust anchor, rejecting certificates without ``BasicConstraints(ca=True)``."""
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    try:
        is_ca = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        is_ca = False
    if not is_ca:
        raise TinyPkiError(
            f"Expected a CA certificate (BasicConstraints ca=True) for ca_cert_pem, got {_name_label(ca_cert.subject)}"
        )
    return ca_cert


def _name_label(name: x509.Name) -> str:
    cn_attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(cn_attrs[0].value) if cn_attrs else name.rfc4514_string()


def _require_aware(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None:
        raise TinyPkiError(f"Expected a timezone-aware {field_name}, got naive {value.isoformat()}")
    return value.astimezone(UTC)


def _result(
    *,
    kind: CertificateKind,
    subject: str,
    issuer: str,
    serial_number: int | None,
    not_before: datetime,
    not_after: datetime | None,
    now: datetime,
    cutoff: datetime,
    reasons: list[tuple[Status, str]],
) -> CertificateStatus:
    status = max((s for s, _ in reasons), key=lambda s: s.severity, default=Status.OK)
    days_remaining = None if not_after is None else math.floor((not_after - now) / timedelta(days=1))
    return CertificateStatus(
        kind=kind,
        subject=subject,
        issuer=issuer,
        serial_number=serial_number,
        not_before=not_before,
        not_after=not_after,
        cutoff=cutoff,
        days_remaining=days_remaining,
        status=status,
        reasons=tuple(message for _, message in reasons),
    )


def _time_reasons(
    now: datetime, not_before: datetime, not_after: datetime, cutoff: datetime
) -> list[tuple[Status, str]]:
    if now < not_before:
        return [(Status.NOT_YET_VALID, f"not valid before {not_before.isoformat()}")]
    if now >= not_after:
        return [(Status.EXPIRED, f"expired on {not_after.isoformat()}")]
    if not_after <= cutoff:
        return [(Status.EXPIRING, f"expires on {not_after.isoformat()}, before the cutoff {cutoff.isoformat()}")]
    return []
