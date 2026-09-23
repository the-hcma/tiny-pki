"""Shared constants for certificate issuance."""

from __future__ import annotations

ALLOWED_KEY_SIZES = (2048, 3072, 4096)

DEFAULT_CA_VALIDITY_DAYS = 3650
DEFAULT_CERT_VALIDITY_DAYS = 1825
DEFAULT_ORGANIZATION_NAME = "tiny-pki"

VALIDITY_PRESETS: list[tuple[int, str]] = [
    (365, "1 year"),
    (730, "2 years"),
    (1095, "3 years"),
    (1460, "4 years"),
    (1825, "5 years"),
]
