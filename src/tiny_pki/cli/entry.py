"""``tiny-pki`` console script: explain a missing ``[cli]`` extra instead of a traceback.

The library needs only ``cryptography``; the REPL and one-shot CLI also need
``prompt-toolkit``, which ships in the optional ``tiny-pki[cli]`` extra. This
module must not import :mod:`tiny_pki.cli.main` at module level, because that
import is exactly what fails without the extra.
"""

from __future__ import annotations

import importlib
import sys
from importlib.util import find_spec

CLI_EXTRA_HINT = (
    "tiny-pki: the command-line tool needs the [cli] extra, which is not installed. "
    "Install it with: pipx install 'tiny-pki[cli]' (or uv tool install 'tiny-pki[cli]', "
    "or pip install 'tiny-pki[cli]')"
)


def main() -> None:
    """Run the CLI, or exit 1 with install instructions when ``prompt-toolkit`` is missing."""
    if find_spec("prompt_toolkit") is None:
        print(CLI_EXTRA_HINT, file=sys.stderr)
        raise SystemExit(1)
    importlib.import_module("tiny_pki.cli.main").main()
