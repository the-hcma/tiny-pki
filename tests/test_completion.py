"""`tiny-pki completion <shell>` prints or installs scripts (issue #23)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from hamcrest import assert_that, contains_string, equal_to, is_, is_not
from pytest import CaptureFixture, MonkeyPatch, raises

from tiny_pki.cli.completion import completion_script, run_completion
from tiny_pki.cli.main import main


def test_completion_emits_a_script_per_shell(capsys: CaptureFixture[str]) -> None:
    for shell, needle, list_case in (
        ("bash", "complete -F _tiny_pki_completion tiny-pki", "list) COMPREPLY="),
        ("zsh", "_tiny-pki()", "list) _values 'target'"),
        ("fish", "complete -c tiny-pki", "__fish_seen_subcommand_from list"),
    ):
        assert_that(run_completion([shell]), equal_to(0))
        out = capsys.readouterr().out
        assert_that(out, contains_string(needle))
        assert_that(out, contains_string("tiny-pki"))
        assert_that(out, contains_string("--version"))
        assert_that(out, contains_string("init"))
        assert_that(out, contains_string(list_case))
        assert_that(out, contains_string("clients"))
        assert_that(out, contains_string("servers"))
        assert_that(out, contains_string("revoked"))
        assert_that(out, is_not(contains_string("Traceback")))


def test_zsh_completion_function_matches_install_basename() -> None:
    script = completion_script("zsh")
    assert_that(script, contains_string("_tiny-pki()"))
    assert_that(script, is_not(contains_string("compdef _tiny")))


def test_completion_force_without_install_is_usage_error(capsys: CaptureFixture[str]) -> None:
    assert_that(run_completion(["bash", "--force", "--json"]), equal_to(2))
    payload = json.loads(capsys.readouterr().err)
    assert_that(payload["error"], equal_to("usage_error"))


def test_completion_requires_a_shell_argument(capsys: CaptureFixture[str]) -> None:
    assert_that(run_completion([]), equal_to(2))
    assert_that(capsys.readouterr().err, contains_string("usage:"))


def test_completion_rejects_unknown_shell(capsys: CaptureFixture[str]) -> None:
    assert_that(run_completion(["tcsh"]), equal_to(2))
    assert_that(capsys.readouterr().err, contains_string("tcsh"))


def test_completion_install_writes_and_is_idempotent(
    monkeypatch: MonkeyPatch, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert_that(run_completion(["bash", "--install", "--json"]), equal_to(0))
    first = json.loads(capsys.readouterr().out)
    assert_that(first["action"], equal_to("written"))
    target = Path(first["path"])
    assert_that(target.is_file(), is_(True))
    assert_that(run_completion(["bash", "--install", "--json"]), equal_to(0))
    second = json.loads(capsys.readouterr().out)
    assert_that(second["action"], equal_to("unchanged"))
    assert_that(target.read_text(encoding="utf-8"), equal_to(completion_script("bash")))


def test_completion_install_refuses_to_clobber_without_force(
    monkeypatch: MonkeyPatch, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    target = tmp_path / "bash-completion" / "completions" / "tiny-pki.bash"
    target.parent.mkdir(parents=True)
    target.write_text("# stale hand-edited content\n", encoding="utf-8")
    assert_that(run_completion(["bash", "--install", "--json"]), equal_to(2))
    payload = json.loads(capsys.readouterr().err)
    assert_that(payload["error"], equal_to("usage_error"))
    assert_that(target.read_text(encoding="utf-8"), equal_to("# stale hand-edited content\n"))
    assert_that(run_completion(["bash", "--install", "--force", "--json"]), equal_to(0))
    written = json.loads(capsys.readouterr().out)
    assert_that(written["action"], equal_to("written"))
    assert_that(target.read_text(encoding="utf-8"), contains_string("_tiny_pki_completion"))


def test_completion_install_human_output_zsh_names_fpath(
    monkeypatch: MonkeyPatch, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    target = tmp_path / "zsh" / "site-functions" / "_tiny-pki"
    assert_that(run_completion(["zsh", "--install"]), equal_to(0))
    out = capsys.readouterr().out
    assert_that(out.splitlines()[0], equal_to(f"written: {target}"))
    assert_that(out, contains_string("fpath"))
    assert_that(out, contains_string("compinit"))


def test_completion_install_ignores_a_relative_xdg_dir(
    monkeypatch: MonkeyPatch, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", "relative/data")
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    monkeypatch.chdir(tmp_path)
    assert_that(run_completion(["bash", "--install", "--json"]), equal_to(0))
    payload = json.loads(capsys.readouterr().out)
    assert_that(
        payload["path"],
        equal_to(str(tmp_path / ".local" / "share" / "bash-completion" / "completions" / "tiny-pki.bash")),
    )
    assert_that((tmp_path / "relative").exists(), is_(False))


def test_completion_json_without_install_returns_the_script(capsys: CaptureFixture[str]) -> None:
    assert_that(run_completion(["fish", "--json"]), equal_to(0))
    payload = json.loads(capsys.readouterr().out)
    assert_that(payload["shell"], equal_to("fish"))
    assert_that(payload["script"], contains_string("complete -c tiny-pki"))


def test_completion_via_main_exits_clean(capsys: CaptureFixture[str]) -> None:
    with raises(SystemExit) as caught:
        main(["completion", "bash"])
    assert_that(caught.value.code, equal_to(0))
    assert_that(capsys.readouterr().out, contains_string("complete -F"))


@pytest.mark.skipif(sys.platform == "win32", reason="symlink / mkfifo are POSIX-only")
def test_completion_install_rejects_a_symlink_target(
    monkeypatch: MonkeyPatch, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    real = tmp_path / "elsewhere" / "stale.bash"
    real.parent.mkdir(parents=True)
    real.write_text("# outside\n", encoding="utf-8")
    target = tmp_path / "bash-completion" / "completions" / "tiny-pki.bash"
    target.parent.mkdir(parents=True)
    target.symlink_to(real)
    assert_that(run_completion(["bash", "--install", "--force", "--json"]), equal_to(1))
    payload = json.loads(capsys.readouterr().err)
    assert_that(payload["error"], equal_to("install_failed"))
    assert_that(payload["message"], contains_string("not a regular file"))
    assert_that(real.read_text(encoding="utf-8"), equal_to("# outside\n"))


@pytest.mark.skipif(sys.platform == "win32", reason="os.mkfifo is POSIX-only")
def test_completion_install_rejects_a_non_regular_target(
    monkeypatch: MonkeyPatch, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    target = tmp_path / "bash-completion" / "completions" / "tiny-pki.bash"
    target.parent.mkdir(parents=True)
    os.mkfifo(target)
    assert_that(run_completion(["bash", "--install", "--force", "--json"]), equal_to(1))
    payload = json.loads(capsys.readouterr().err)
    assert_that(payload["error"], equal_to("install_failed"))
    assert_that(payload["message"], contains_string("not a regular file"))
