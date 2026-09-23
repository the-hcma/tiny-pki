"""prompt_toolkit completer for the tiny-pki REPL."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.document import Document

from tiny_pki.cli.theme import Theme

_CMD_THEN_REST = re.compile(r"^(\S+)(\s+)(.*)$", re.DOTALL)


@dataclass(frozen=True)
class CmdCtx:
    """Completing a command name."""

    partial: str


@dataclass(frozen=True)
class ArgCtx:
    """Completing arguments for a known command."""

    command: str
    partial: str


def parse_completion_buffer(buf: str) -> CmdCtx | ArgCtx:
    """Classify the current input buffer for completion."""
    stripped = buf.lstrip()
    if not stripped:
        return CmdCtx(partial="")
    match = _CMD_THEN_REST.match(stripped)
    if match is None:
        return CmdCtx(partial=stripped)
    command, _ws, rest = match.group(1), match.group(2), match.group(3)
    if not rest or stripped[-1:].isspace():
        return ArgCtx(command=command, partial="")
    return ArgCtx(command=command, partial=rest.split()[-1])


class ReplCompleter(Completer):
    """Complete command names and optional argument tokens."""

    def __init__(
        self,
        *,
        commands: Iterable[str],
        theme: Theme,
        argument_tokens: Callable[[str], Iterable[str]] | None = None,
    ) -> None:
        self._commands = tuple(sorted(commands))
        self._theme = theme

        def _empty_tokens(_cmd: str) -> tuple[str, ...]:
            return ()

        self._argument_tokens: Callable[[str], Iterable[str]] = argument_tokens or _empty_tokens

    def get_completions(self, document: Document, complete_event: object) -> Iterable[Completion]:
        del complete_event
        ctx = parse_completion_buffer(document.text_before_cursor)
        if isinstance(ctx, CmdCtx):
            style = self._theme.completion_command_style()
            for cmd in self._commands:
                if cmd.startswith(ctx.partial):
                    yield Completion(cmd, start_position=-len(ctx.partial), style=style)
            return
        style = self._theme.completion_parameter_style()
        for token in self._argument_tokens(ctx.command):
            if token.startswith(ctx.partial):
                yield Completion(token, start_position=-len(ctx.partial), style=style)
