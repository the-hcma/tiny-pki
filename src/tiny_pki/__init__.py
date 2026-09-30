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
    DEFAULT_CRL_VALIDITY_DAYS,
    DEFAULT_INTERMEDIATE_VALIDITY_DAYS,
    DEFAULT_KEY_TYPE,
    DEFAULT_LEAF_KEY_SIZE,
    DEFAULT_OCSP_VALIDITY_DAYS,
    DEFAULT_ORGANIZATION_NAME,
    DEFAULT_SERVER_VALIDITY_DAYS,
    KEY_TYPES,
    MAX_CA_WARNING_DAYS,
    MAX_CLIENT_VALIDITY_DAYS,
    MAX_LEAF_WARNING_DAYS,
    MAX_OCSP_VALIDITY_DAYS,
    MAX_SERVER_VALIDITY_DAYS,
    MAX_STORE_CRL_VALIDITY_DAYS,
    MAX_VALIDITY_DAYS,
    MIN_PKCS12_PASSWORD_LENGTH,
    VALIDITY_PRESETS,
    KeyType,
)
from tiny_pki.errors import TinyPkiError, TinyPkiWarning
from tiny_pki.inspect import (
    CsrSummary,
    get_certificate_expiry,
    get_certificate_fingerprint,
    get_certificate_issuer,
    get_certificate_metadata,
    get_certificate_sans,
    get_certificate_serial_number,
    get_certificate_subject,
    inspect_csr,
    is_certificate_self_signed,
)
from tiny_pki.issue import (
    generate_ca_certificate,
    generate_client_certificate,
    generate_intermediate_ca_certificate,
    generate_server_certificate,
    max_leaf_validity_days,
    sign_client_csr,
    sign_intermediate_csr,
    sign_server_csr,
)
from tiny_pki.ocsp import generate_ocsp_response, generate_ocsp_response_for_certificate
from tiny_pki.revoke import generate_crl
from tiny_pki.version import package_version

__version__ = package_version()

__all__ = [
    "ALLOWED_KEY_SIZES",
    "APPLE_MAX_SERVER_VALIDITY_DAYS",
    "CLOCK_SKEW_BACKDATE",
    "CertificateKind",
    "CertificateStatus",
    "CsrSummary",
    "DEFAULT_CA_KEY_SIZE",
    "DEFAULT_CA_VALIDITY_DAYS",
    "DEFAULT_CLIENT_VALIDITY_DAYS",
    "DEFAULT_CRL_VALIDITY_DAYS",
    "DEFAULT_INTERMEDIATE_VALIDITY_DAYS",
    "DEFAULT_KEY_TYPE",
    "DEFAULT_LEAF_KEY_SIZE",
    "DEFAULT_OCSP_VALIDITY_DAYS",
    "DEFAULT_ORGANIZATION_NAME",
    "DEFAULT_SERVER_VALIDITY_DAYS",
    "KEY_TYPES",
    "KeyType",
    "MAX_CA_WARNING_DAYS",
    "MAX_CLIENT_VALIDITY_DAYS",
    "MAX_LEAF_WARNING_DAYS",
    "MAX_OCSP_VALIDITY_DAYS",
    "MAX_SERVER_VALIDITY_DAYS",
    "MAX_STORE_CRL_VALIDITY_DAYS",
    "MAX_VALIDITY_DAYS",
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
    "generate_intermediate_ca_certificate",
    "generate_ocsp_response",
    "generate_ocsp_response_for_certificate",
    "generate_pkcs12",
    "generate_server_certificate",
    "get_certificate_expiry",
    "get_certificate_fingerprint",
    "get_certificate_issuer",
    "get_certificate_metadata",
    "get_certificate_sans",
    "get_certificate_serial_number",
    "get_certificate_subject",
    "inspect_csr",
    "is_certificate_self_signed",
    "max_leaf_validity_days",
    "sign_client_csr",
    "sign_intermediate_csr",
    "sign_server_csr",
    "worst_status",
]
