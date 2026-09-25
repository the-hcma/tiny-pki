"""Smoke tests for the scaffold package."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import importlib
import re
import tomllib
from importlib import metadata
from pathlib import Path

from hamcrest import assert_that, contains_string, equal_to, matches_regexp, not_none
from pytest import CaptureFixture, MonkeyPatch

import tiny_pki
from tiny_pki import version as version_module
from tiny_pki.cli.main import main


def test_package_version_matches_distribution_metadata() -> None:
    assert_that(tiny_pki.__version__, not_none())
    assert_that(tiny_pki.__version__, equal_to(metadata.version("tiny-pki")))
    with (Path(__file__).resolve().parents[1] / "pyproject.toml").open("rb") as pyproject:
        assert_that(tiny_pki.__version__, equal_to(tomllib.load(pyproject)["project"]["version"]))


def test_package_version_is_derived_not_hard_coded(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(version_module, "package_version", lambda: "9.9.9-test")
    try:
        assert_that(importlib.reload(tiny_pki).__version__, equal_to("9.9.9-test"))
    finally:
        monkeypatch.undo()
        importlib.reload(tiny_pki)
    assert_that(tiny_pki.__version__, equal_to(metadata.version("tiny-pki")))


def test_cli_version_exits_clean(capsys: CaptureFixture[str], monkeypatch: MonkeyPatch) -> None:
    version_module.get_build_info.cache_clear()
    monkeypatch.setenv("TINY_PKI_GIT_SHA", "feedface0001")
    main(["--version"])
    captured = capsys.readouterr()
    assert_that(captured.out.strip(), equal_to(f"tiny-pki {tiny_pki.__version__} (feedface0001)"))
    version_module.get_build_info.cache_clear()


def test_cli_version_includes_commit_when_no_override(capsys: CaptureFixture[str]) -> None:
    version_module.get_build_info.cache_clear()
    main(["--version"])
    out = capsys.readouterr().out.strip()
    assert_that(out, contains_string(f"tiny-pki {tiny_pki.__version__} ("))
    assert_that(out, matches_regexp(rf"^tiny-pki {re.escape(tiny_pki.__version__)} \(([0-9a-f]{{7,12}}|unknown)\)$"))
    version_module.get_build_info.cache_clear()
