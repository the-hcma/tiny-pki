"""Shared constants for certificate issuance.

Validity limits follow current industry guidance (see ``docs/defaults.md``):
CA/Browser Forum SC-081 caps public TLS server certificates at 200 days from
2026-03-15, Let's Encrypt issues 90-day certificates, and Apple platforms reject
TLS server certificates valid for more than 825 days even from private CAs.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Literal

KeyType = Literal["rsa", "ec-p256"]

ALLOWED_KEY_SIZES = (2048, 3072, 4096)

APPLE_MAX_SERVER_VALIDITY_DAYS = 825

CLOCK_SKEW_BACKDATE = timedelta(minutes=5)

DEFAULT_CA_KEY_SIZE = 4096
DEFAULT_CA_VALIDITY_DAYS = 3650
DEFAULT_CLIENT_VALIDITY_DAYS = 397
DEFAULT_CRL_VALIDITY_DAYS = 30
DEFAULT_KEY_TYPE: KeyType = "rsa"
DEFAULT_LEAF_KEY_SIZE = 3072
DEFAULT_OCSP_VALIDITY_DAYS = 7
DEFAULT_ORGANIZATION_NAME = "tiny-pki"
DEFAULT_SERVER_VALIDITY_DAYS = 90

KEY_TYPES: tuple[KeyType, ...] = ("rsa", "ec-p256")

MAX_CA_WARNING_DAYS = 180
MAX_CLIENT_VALIDITY_DAYS = 825
MAX_LEAF_WARNING_DAYS = 30
MAX_OCSP_VALIDITY_DAYS = 30
MAX_SERVER_VALIDITY_DAYS = 200
MAX_STORE_CRL_VALIDITY_DAYS = 365
MAX_VALIDITY_DAYS = 36500

MIN_PKCS12_PASSWORD_LENGTH = 16

VALIDITY_PRESETS: list[tuple[int, str]] = [
    (90, "90 days"),
    (180, "180 days"),
    (397, "1 year"),
    (730, "2 years"),
    (825, "825 days"),
]
