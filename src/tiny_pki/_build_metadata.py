"""Optional release-time stamps baked into wheels or sdists.

``scripts/embed_build_metadata`` overwrites this file before packaging so
``tiny-pki --version`` still reports a commit when ``.git`` is absent (for
example after ``pipx install`` from PyPI). Empty strings mean "unset" and
:mod:`tiny_pki.version` falls back to env, then ``git``, then ``unknown``.
"""

from __future__ import annotations

EMBEDDED_COMMIT: str = ""
EMBEDDED_VERSION: str = ""
