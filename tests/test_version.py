"""Build-metadata resolution: env override, embedded stamp, git, then unknown."""

# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false
# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

from pathlib import Path

import pytest
from hamcrest import assert_that, contains_string, equal_to, is_, is_not, matches_regexp
from pytest import CaptureFixture, MonkeyPatch

from tiny_pki import version as version_module
from tiny_pki.cli.main import main
from tiny_pki.version import format_cli_version_line, git_commit, package_version


def test_git_commit_prefers_env_override_and_shortens(tmp_path: Path) -> None:
    sha = "0123456789abcdef0123456789abcdef01234567"
    assert_that(
        git_commit(environ={"TINY_PKI_GIT_SHA": sha}, repository=tmp_path),
        equal_to(sha[:12]),
    )


def test_git_commit_ignores_ambient_github_sha(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(version_module._build_metadata, "EMBEDDED_COMMIT", "abcdef123456", raising=False)
    unrelated = "9999999999999999999999999999999999999999"
    assert_that(
        git_commit(environ={"GITHUB_SHA": unrelated}, repository=tmp_path),
        equal_to("abcdef123456"),
    )


def test_git_commit_falls_back_to_embedded(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(version_module._build_metadata, "EMBEDDED_COMMIT", "abcdef123456", raising=False)
    assert_that(git_commit(environ={}, repository=tmp_path), equal_to("abcdef123456"))


def test_git_commit_unknown_without_checkout_env_or_embed(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(version_module._build_metadata, "EMBEDDED_COMMIT", "", raising=False)
    assert_that(git_commit(environ={}, repository=tmp_path), equal_to("unknown"))


def test_git_commit_reads_the_checkout() -> None:
    commit = git_commit(environ={})
    assert_that(commit, is_not(equal_to("unknown")))
    assert_that(commit, matches_regexp(r"^[0-9a-f]{7,12}$"))


def test_package_version_prefers_embedded(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(version_module._build_metadata, "EMBEDDED_VERSION", "9.9.9", raising=False)
    assert_that(package_version(), equal_to("9.9.9"))


def test_package_version_reads_pyproject_when_not_installed(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(version_module._build_metadata, "EMBEDDED_VERSION", "", raising=False)

    def _raise(_name: str) -> str:
        raise version_module.PackageNotFoundError

    monkeypatch.setattr(version_module, "version", _raise)
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "1.2.3"\n', encoding="utf-8")
    assert_that(package_version(pyproject_path=tmp_path / "pyproject.toml"), equal_to("1.2.3"))


def test_format_cli_version_line_shape(monkeypatch: MonkeyPatch) -> None:
    version_module.get_build_info.cache_clear()
    monkeypatch.setenv("TINY_PKI_GIT_SHA", "deadbeefcafe")
    monkeypatch.setattr(version_module._build_metadata, "EMBEDDED_VERSION", "0.1.0", raising=False)
    version_module.get_build_info.cache_clear()
    line = format_cli_version_line(prog="tiny-pki")
    assert_that(line, equal_to("tiny-pki 0.1.0 (deadbeefcafe)"))
    version_module.get_build_info.cache_clear()


def test_cli_version_flag(capsys: CaptureFixture[str], monkeypatch: MonkeyPatch) -> None:
    version_module.get_build_info.cache_clear()
    monkeypatch.setenv("TINY_PKI_GIT_SHA", "aabbccddeeff")
    main(["--version"])
    out = capsys.readouterr().out.strip()
    assert_that(out, contains_string("tiny-pki "))
    assert_that(out, contains_string("(aabbccddeeff)"))
    assert_that(out.startswith("tiny-pki "), is_(True))
    version_module.get_build_info.cache_clear()


@pytest.mark.parametrize("value", ["abc\nEVIL", "\x1b[31mred", "not-a-sha", "abc123", "g" * 12, "a" * 41])
def test_git_commit_rejects_non_hex_override(tmp_path: Path, value: str) -> None:
    assert_that(git_commit(environ={"TINY_PKI_GIT_SHA": value}, repository=tmp_path), equal_to("unknown"))


def test_git_commit_rejects_non_hex_embedded(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(version_module._build_metadata, "EMBEDDED_COMMIT", "abc\nEVIL", raising=False)
    assert_that(git_commit(environ={}, repository=tmp_path), equal_to("unknown"))


def test_git_commit_accepts_short_uppercase_hex(tmp_path: Path) -> None:
    assert_that(git_commit(environ={"TINY_PKI_GIT_SHA": "ABCDEF1"}, repository=tmp_path), equal_to("abcdef1"))
