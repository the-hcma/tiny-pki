"""tiny-pki — private CA crypto primitives and CLI.

Core APIs are bytes-in / bytes-out (no filesystem, no Django). Extracted and
generalized under MIT from ``the-hcma/my-tracks`` ``app/pki.py``.
"""

from __future__ import annotations

from tiny_pki.bundle import generate_pkcs12
from tiny_pki.constants import (
    ALLOWED_KEY_SIZES,
    DEFAULT_CA_VALIDITY_DAYS,
    DEFAULT_CERT_VALIDITY_DAYS,
    DEFAULT_ORGANIZATION_NAME,
    VALIDITY_PRESETS,
)
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
)
from tiny_pki.revoke import generate_crl

__version__ = "0.1.0"

__all__ = [
    "ALLOWED_KEY_SIZES",
    "DEFAULT_CA_VALIDITY_DAYS",
    "DEFAULT_CERT_VALIDITY_DAYS",
    "DEFAULT_ORGANIZATION_NAME",
    "VALIDITY_PRESETS",
    "__version__",
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
]
