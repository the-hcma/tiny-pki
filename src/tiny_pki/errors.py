"""Exception and warning categories raised by tiny-pki."""

from __future__ import annotations


class TinyPkiError(ValueError):
    """Input or policy rejection (bad name or SAN, leaf outliving its CA, short password, ...).

    The message says what was expected and what was received. It never contains
    key material, so it is safe to show to end users. Subclassing ``ValueError``
    keeps ``except ValueError`` callers working.
    """


class TinyPkiWarning(UserWarning):
    """Issuance succeeded, but the result may be rejected by some relying parties."""
