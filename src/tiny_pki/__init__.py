"""tiny-pki — private CA crypto primitives and CLI.

Core APIs are bytes-in / bytes-out (no filesystem, no Django). Extracted and
generalized under MIT from ``the-hcma/my-tracks`` ``app/pki.py``.
"""

from __future__ import annotations

from tiny_pki.bundle import generate_pkcs12
from tiny_pki.check import (
    CertificateKind,
    CertificateStatus,
    Status,
    check_certificate,
    check_crl,
    default_warning_window,
    worst_status,
)
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
    MAX_CA_WARNING_DAYS,
    MAX_CLIENT_VALIDITY_DAYS,
    MAX_LEAF_WARNING_DAYS,
    MAX_SERVER_VALIDITY_DAYS,
    MIN_PKCS12_PASSWORD_LENGTH,
    VALIDITY_PRESETS,
)
from tiny_pki.errors import TinyPkiError, TinyPkiWarning
from tiny_pki.inspect import (
    get_certificate_expiry,
    get_certificate_fingerprint,
    get_certificate_issuer,
    get_certificate_metadata,
    get_certificate_sans,
    get_certificate_serial_number,
    get_certificate_subject,
    is_certificate_self_signed,
)
from tiny_pki.issue import (
    generate_ca_certificate,
    generate_client_certificate,
    generate_server_certificate,
    max_leaf_validity_days,
)
from tiny_pki.revoke import generate_crl
from tiny_pki.version import package_version

__version__ = package_version()

__all__ = [
    "ALLOWED_KEY_SIZES",
    "APPLE_MAX_SERVER_VALIDITY_DAYS",
    "CLOCK_SKEW_BACKDATE",
    "CertificateKind",
    "CertificateStatus",
    "DEFAULT_CA_KEY_SIZE",
    "DEFAULT_CA_VALIDITY_DAYS",
    "DEFAULT_CLIENT_VALIDITY_DAYS",
    "DEFAULT_LEAF_KEY_SIZE",
    "DEFAULT_ORGANIZATION_NAME",
    "DEFAULT_SERVER_VALIDITY_DAYS",
    "MAX_CA_WARNING_DAYS",
    "MAX_CLIENT_VALIDITY_DAYS",
    "MAX_LEAF_WARNING_DAYS",
    "MAX_SERVER_VALIDITY_DAYS",
    "MIN_PKCS12_PASSWORD_LENGTH",
    "Status",
    "TinyPkiError",
    "TinyPkiWarning",
    "VALIDITY_PRESETS",
    "__version__",
    "check_certificate",
    "check_crl",
    "default_warning_window",
    "generate_ca_certificate",
    "generate_client_certificate",
    "generate_crl",
    "generate_pkcs12",
    "generate_server_certificate",
    "get_certificate_expiry",
    "get_certificate_fingerprint",
    "get_certificate_issuer",
    "get_certificate_metadata",
    "get_certificate_sans",
    "get_certificate_serial_number",
    "get_certificate_subject",
    "is_certificate_self_signed",
    "max_leaf_validity_days",
    "worst_status",
]
