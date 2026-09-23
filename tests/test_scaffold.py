"""Smoke tests for the scaffold package."""

from __future__ import annotations

from hamcrest import assert_that, equal_to, not_none
from pytest import CaptureFixture

import tiny_pki
from tiny_pki.cli.main import main


def test_package_version_is_set() -> None:
    assert_that(tiny_pki.__version__, not_none())
    assert_that(tiny_pki.__version__, equal_to("0.1.0"))


def test_cli_version_exits_clean(capsys: CaptureFixture[str]) -> None:
    main(["--version"])
    captured = capsys.readouterr()
    assert_that(captured.out.strip(), equal_to("0.1.0"))
