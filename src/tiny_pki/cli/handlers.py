"""Stub PKI handlers — replaced by the CLI-commands stack layer.

Shell chrome (#8) can import this module; real verbs land in #9.
"""

from __future__ import annotations

from tiny_pki.cli.theme import Theme
from tiny_pki.store import CertificateStore


class HandlerNotReadyError(RuntimeError):
    """Raised until the CLI-commands layer implements PKI verbs."""


def dispatch(
    command: str,
    args: list[str],
    *,
    store: CertificateStore | None,
    theme: Theme,
) -> None:
    """Placeholder until init/create/show/… handlers are wired."""
    del args, store, theme
    raise HandlerNotReadyError(f"Command {command!r} is not implemented yet (see issue #9)")
