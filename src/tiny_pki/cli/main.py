"""tiny-pki CLI entrypoint — REPL-first launcher (domesti-bot style)."""

from __future__ import annotations

import argparse
import os
import shlex
import sys
from pathlib import Path

from prompt_toolkit import HTML, PromptSession
from prompt_toolkit.enums import EditingMode
from prompt_toolkit.history import FileHistory, History, InMemoryHistory
from prompt_toolkit.patch_stdout import patch_stdout

from tiny_pki.cli.commands import COMMAND_HELP, COMMANDS, PKI_COMMANDS
from tiny_pki.cli.completer import ReplCompleter
from tiny_pki.cli.completion import run_completion
from tiny_pki.cli.theme import Theme, stdout_color_enabled
from tiny_pki.store import CertificateStore, require_store_path
from tiny_pki.version import format_cli_version_line

_HISTORY_PATH = Path.home() / ".cache" / "tiny-pki" / "history"


def main(argv: list[str] | None = None) -> None:
    """Parse launcher flags and enter the REPL (or run a one-shot command)."""
    parser = _build_arg_parser()
    args, rest = parser.parse_known_args(argv)

    if args.version:
        print(format_cli_version_line(prog="tiny-pki"))
        return

    if rest and rest[0] == "completion":
        raise SystemExit(run_completion(rest[1:]))

    theme = Theme(enabled=stdout_color_enabled(args.color))
    store_path = args.store or os.environ.get("TINY_PKI_STORE")
    store: CertificateStore | None = None
    if store_path:
        try:
            store = CertificateStore(require_store_path(store_path))
        except ValueError as exc:
            print(theme.error(str(exc)), file=sys.stderr)
            raise SystemExit(1) from None

    edit_mode = _normalize_edit_mode(args.edit_mode)

    if rest:
        if _dispatch_parts(rest, store=store, theme=theme, edit_mode_holder=[edit_mode]) is False:
            raise SystemExit(1)
        return

    _run_repl(store=store, theme=theme, edit_mode=edit_mode)


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tiny-pki",
        description="Private CA toolkit: issue, show, revoke, delete certificates.",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print package version and git commit, then exit.",
    )
    parser.add_argument(
        "--store",
        metavar="DIR",
        help="Certificate store directory (or set TINY_PKI_STORE).",
    )
    parser.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        default="auto",
        help="Terminal colors (default: auto when stdout is a TTY).",
    )
    parser.add_argument(
        "--edit-mode",
        default=os.environ.get("TINY_PKI_EDIT_MODE", "vim"),
        help="Line-editing bindings: vim (default) or emacs.",
    )
    return parser


def _normalize_edit_mode(raw: str) -> str:
    value = (raw or "vim").strip().lower()
    if value in {"e", "emacs"}:
        return "emacs"
    return "vim"


def _repl_history(theme: Theme) -> History:
    """Return FileHistory when the cache dir is writable, else in-memory history."""
    try:
        _HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
        return FileHistory(str(_HISTORY_PATH))
    except OSError as exc:
        print(theme.warn(f"history disabled ({exc}); using in-memory history"), file=sys.stderr)
        return InMemoryHistory()


def _run_repl(*, store: CertificateStore | None, theme: Theme, edit_mode: str) -> None:
    mode_holder = [edit_mode]
    session: PromptSession[str] = PromptSession(
        history=_repl_history(theme),
        completer=ReplCompleter(
            commands=COMMANDS,
            theme=theme,
            argument_tokens=lambda cmd: _argument_tokens(cmd, store),
        ),
        editing_mode=EditingMode.EMACS if edit_mode == "emacs" else EditingMode.VI,
    )

    print(theme.dim(f"{format_cli_version_line(prog='tiny-pki')} — type help"), flush=True)
    if store is None:
        print(theme.warn("No --store / TINY_PKI_STORE set; write commands will fail."), flush=True)
    else:
        print(theme.dim(f"store: {store.root}"), flush=True)

    with patch_stdout():
        while True:
            try:
                line = session.prompt(_prompt_markup(theme))
            except (EOFError, KeyboardInterrupt):
                print()
                return
            except OSError as exc:
                print(theme.error(f"prompt error: {exc}"), file=sys.stderr)
                return
            if not line.strip():
                continue
            try:
                parts = shlex.split(line)
            except ValueError as exc:
                print(theme.error(f"parse error: {exc}"), file=sys.stderr)
                continue
            if _dispatch_parts(parts, store=store, theme=theme, edit_mode_holder=mode_holder) is None:
                return
            session.editing_mode = EditingMode.EMACS if mode_holder[0] == "emacs" else EditingMode.VI


def _prompt_markup(theme: Theme) -> HTML | str:
    """Build the REPL prompt; plain text when coloring is disabled."""
    if not theme.enabled:
        return "tiny-pki > "
    return HTML('<style fg="ansicyan"><b>tiny-pki</b></style><style fg="ansibrightblack"> &gt; </style>')


def _argument_tokens(command: str, store: CertificateStore | None) -> tuple[str, ...]:
    fixed: tuple[str, ...] = ()
    if command == "create":
        return ("client", "server")
    if command == "edit-mode":
        return ("emacs", "vim")
    if command == "export":
        fixed = ("pem", "p12")
    elif command == "list":
        return ("ca", "certs", "clients", "revoked", "servers")
    elif command == "show":
        fixed = ("ca", "certs", "clients", "crl", "revoked", "servers")
    names: tuple[str, ...] = ()
    if command in {"delete", "export", "inspect", "revoke", "show"} and store is not None:
        try:
            names = tuple(sorted({e.common_name for e in store.list_certificates()}))
        except (FileNotFoundError, KeyError, OSError, ValueError):
            names = ()
    return tuple(sorted({*fixed, *names}))


def _dispatch_parts(
    parts: list[str],
    *,
    store: CertificateStore | None,
    theme: Theme,
    edit_mode_holder: list[str],
) -> bool | None:
    """Handle one REPL/one-shot argv list.

    Returns ``True`` on success, ``False`` on failure, ``None`` to leave the REPL.
    """
    if not parts:
        return True

    command = parts[0]
    args = parts[1:]

    if command in {"exit", "quit"}:
        return None
    if command == "help":
        _print_help(theme)
        return True
    if command == "completion":
        return run_completion(args) == 0
    if command == "clear":
        # Screen control is independent of color theming (--color never / NO_COLOR).
        if sys.stdout.isatty():
            print("\033[2J\033[H", end="", flush=True)
        return True
    if command == "edit-mode":
        if not args:
            print(theme.dim(f"edit-mode is {edit_mode_holder[0]}"))
            return True
        edit_mode_holder[0] = _normalize_edit_mode(args[0])
        print(theme.ok(f"edit-mode {edit_mode_holder[0]}"))
        return True

    if command in PKI_COMMANDS:
        return _dispatch_pki(command, args, store=store, theme=theme)

    print(theme.error(f"Unknown command {command!r}; type help"), file=sys.stderr)
    return False


def _dispatch_pki(
    command: str,
    args: list[str],
    *,
    store: CertificateStore | None,
    theme: Theme,
) -> bool:
    """Delegate to command handlers (filled in by the CLI-commands layer)."""
    from tiny_pki.cli import handlers

    try:
        handlers.dispatch(command, args, store=store, theme=theme)
    except handlers.HandlerNotReadyError as exc:
        print(theme.warn(str(exc)), file=sys.stderr)
        return False
    except (FileNotFoundError, KeyError, ValueError, OSError) as exc:
        print(theme.error(str(exc)), file=sys.stderr)
        return False
    return True


def _print_help(theme: Theme) -> None:
    width = max(len(name) for name, _ in COMMAND_HELP)
    for name, description in COMMAND_HELP:
        print(f"  {theme.ok(name.ljust(width))}  {description}")


if __name__ == "__main__":
    main()
