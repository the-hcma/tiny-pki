"""`tiny-pki` console script without and with the optional [cli] extra (issue #54)."""

from __future__ import annotations

import sys
from importlib.machinery import ModuleSpec

import pytest
from hamcrest import assert_that, contains_string, equal_to, starts_with
from pytest import CaptureFixture, MonkeyPatch

from tiny_pki.cli import entry


def test_missing_cli_extra_exits_with_install_hint(capsys: CaptureFixture[str], monkeypatch: MonkeyPatch) -> None:
    def find_spec(name: str) -> ModuleSpec | None:
        return None if name == "prompt_toolkit" else ModuleSpec(name, None)

    monkeypatch.setattr(entry, "find_spec", find_spec)
    with pytest.raises(SystemExit) as exited:
        entry.main()
    assert_that(exited.value.code, equal_to(1))
    err = capsys.readouterr().err
    assert_that(err, contains_string("pipx install 'tiny-pki[cli]'"))
    assert_that(err, equal_to(entry.CLI_EXTRA_HINT + "\n"))


def test_installed_cli_extra_runs_the_cli(capsys: CaptureFixture[str], monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", [sys.argv[0], "--version"])
    entry.main()
    assert_that(capsys.readouterr().out, starts_with("tiny-pki "))
