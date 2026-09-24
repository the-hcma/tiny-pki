"""Warning categories emitted by tiny-pki."""

from __future__ import annotations


class TinyPkiWarning(UserWarning):
    """Issuance succeeded, but the result may be rejected by some relying parties."""
