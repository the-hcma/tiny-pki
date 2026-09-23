"""ANSI theme for the tiny-pki REPL (TTY + NO_COLOR + --color)."""

from __future__ import annotations

import os
import sys


class Theme:
    """Stdout/stderr styling when coloring is enabled."""

    def __init__(self, *, enabled: bool) -> None:
        self.enabled = enabled

    def completion_command_style(self) -> str:
        return "fg:ansicyan" if self.enabled else ""

    def completion_parameter_style(self) -> str:
        return "fg:ansiyellow" if self.enabled else ""

    def dim(self, text: str) -> str:
        return self._wrap(text, "\033[2m", "\033[0m")

    def error(self, text: str) -> str:
        return self._wrap(text, "\033[31m", "\033[0m")

    def ok(self, text: str) -> str:
        return self._wrap(text, "\033[32m", "\033[0m")

    def warn(self, text: str) -> str:
        return self._wrap(text, "\033[33m", "\033[0m")

    def _wrap(self, text: str, start: str, end: str) -> str:
        if not self.enabled:
            return text
        return f"{start}{text}{end}"


def stdout_color_enabled(mode: str) -> bool:
    """Resolve ``auto`` / ``always`` / ``never`` against TTY and ``NO_COLOR``.

    ``auto`` requires both stdout and stderr to be TTYs so redirected error
    streams do not receive ANSI escapes when stdout is still a terminal.
    """
    if mode == "always":
        return True
    if mode == "never":
        return False
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty() and sys.stderr.isatty()
