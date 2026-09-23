"""tiny-pki CLI entrypoint (scaffold).

Full REPL (prompt_toolkit, colors, tab completion) lands in a follow-up.
"""

from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> None:
    """Parse launcher flags and print a short status message."""
    parser = argparse.ArgumentParser(
        prog="tiny-pki",
        description="Private CA toolkit: issue, show, revoke, delete certificates.",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print package version and exit.",
    )
    parser.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        default="auto",
        help="Terminal colors (default: auto when stdout is a TTY).",
    )
    args = parser.parse_args(argv)

    if args.version:
        from tiny_pki import __version__

        print(__version__)
        return

    print(
        "tiny-pki: scaffold only — REPL (init/create/show/revoke/delete) coming next.",
        file=sys.stderr,
    )
    raise SystemExit(0)


if __name__ == "__main__":
    main()
