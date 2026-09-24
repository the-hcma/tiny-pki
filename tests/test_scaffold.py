"""Smoke tests for the scaffold package."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

from hamcrest import assert_that, contains_string, equal_to, matches_regexp, not_none
from pytest import CaptureFixture, MonkeyPatch

import tiny_pki
from tiny_pki import version as version_module
from tiny_pki.cli.main import main


def test_package_version_is_set() -> None:
    assert_that(tiny_pki.__version__, not_none())
    assert_that(tiny_pki.__version__, equal_to("0.1.0"))


def test_cli_version_exits_clean(capsys: CaptureFixture[str], monkeypatch: MonkeyPatch) -> None:
    version_module.get_build_info.cache_clear()
    monkeypatch.setenv("TINY_PKI_GIT_SHA", "feedface0001")
    main(["--version"])
    captured = capsys.readouterr()
    assert_that(captured.out.strip(), equal_to("tiny-pki 0.1.0 (feedface0001)"))
    version_module.get_build_info.cache_clear()


def test_cli_version_includes_commit_when_no_override(capsys: CaptureFixture[str]) -> None:
    version_module.get_build_info.cache_clear()
    main(["--version"])
    out = capsys.readouterr().out.strip()
    assert_that(out, contains_string("tiny-pki 0.1.0 ("))
    assert_that(out, matches_regexp(r"^tiny-pki 0\.1\.0 \(([0-9a-f]{7,12}|unknown)\)$"))
    version_module.get_build_info.cache_clear()
