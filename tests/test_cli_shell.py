"""Tests for CLI shell chrome (theme, completer, launcher flags)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from hamcrest import assert_that, contains_string, equal_to, has_item, instance_of, is_
from prompt_toolkit.document import Document
from prompt_toolkit.history import InMemoryHistory
from pytest import CaptureFixture, MonkeyPatch, raises

from tiny_pki.cli import main as main_mod
from tiny_pki.cli.commands import COMMANDS, PKI_COMMANDS
from tiny_pki.cli.completer import ArgCtx, CmdCtx, ReplCompleter, parse_completion_buffer
from tiny_pki.cli.main import main
from tiny_pki.cli.theme import Theme, stdout_color_enabled
from tiny_pki.store import CertificateStore


def test_color_auto_never_always(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    monkeypatch.setattr("sys.stderr.isatty", lambda: True)
    assert_that(stdout_color_enabled("always"), is_(True))
    assert_that(stdout_color_enabled("never"), is_(False))
    assert_that(stdout_color_enabled("auto"), is_(True))
    monkeypatch.setattr("sys.stderr.isatty", lambda: False)
    assert_that(stdout_color_enabled("auto"), is_(False))
    monkeypatch.setattr("sys.stderr.isatty", lambda: True)
    monkeypatch.setenv("NO_COLOR", "1")
    assert_that(stdout_color_enabled("auto"), is_(False))


def test_theme_wraps_when_enabled() -> None:
    on = Theme(enabled=True)
    off = Theme(enabled=False)
    assert_that(off.ok("ok"), equal_to("ok"))
    assert_that(on.ok("ok"), contains_string("ok"))
    assert_that(on.ok("ok") != "ok", is_(True))


def test_parse_completion_buffer() -> None:
    assert_that(parse_completion_buffer(""), equal_to(CmdCtx(partial="")))
    assert_that(parse_completion_buffer("sh"), equal_to(CmdCtx(partial="sh")))
    assert_that(parse_completion_buffer("show "), equal_to(ArgCtx(command="show", partial="")))
    assert_that(parse_completion_buffer("show ca"), equal_to(ArgCtx(command="show", partial="ca")))
    assert_that(parse_completion_buffer("show\tca"), equal_to(ArgCtx(command="show", partial="ca")))
    assert_that(parse_completion_buffer("show\t"), equal_to(ArgCtx(command="show", partial="")))
    assert_that(
        parse_completion_buffer("create client al"),
        equal_to(ArgCtx(command="create", partial="al")),
    )


def test_repl_completer_commands() -> None:
    theme = Theme(enabled=False)
    completer = ReplCompleter(commands=COMMANDS, theme=theme)
    names = [c.text for c in completer.get_completions(Document("sh", 2), None)]
    assert_that("show" in names, is_(True))


def test_commands_table_sorted() -> None:
    assert_that(COMMANDS, equal_to(tuple(sorted(COMMANDS))))
    assert_that("init" in PKI_COMMANDS, is_(True))
    assert_that("renew-crl" in COMMANDS, is_(True))
    assert_that("renew-crl" in PKI_COMMANDS, is_(True))


def test_argument_tokens_keep_fixed_when_store_set(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "ca")
    theme = Theme(enabled=False)

    def tokens(cmd: str) -> tuple[str, ...]:
        from tiny_pki.cli import main as main_mod

        return main_mod._argument_tokens(cmd, store)  # pyright: ignore[reportPrivateUsage]

    completer = ReplCompleter(commands=COMMANDS, theme=theme, argument_tokens=tokens)
    export_names = [c.text for c in completer.get_completions(Document("export ", 7), None)]
    assert_that(export_names, has_item("pem"))
    assert_that(export_names, has_item("p12"))
    show_names = [c.text for c in completer.get_completions(Document("show ", 5), None)]
    assert_that(show_names, has_item("ca"))
    assert_that(show_names, has_item("certs"))
    assert_that(show_names, has_item("crl"))


def test_version_flag() -> None:
    buf = StringIO()
    with redirect_stdout(buf):
        main(["--version"])
    assert_that(buf.getvalue().strip(), equal_to("0.1.0"))


def test_one_shot_help() -> None:
    buf = StringIO()
    with redirect_stdout(buf):
        main(["--color", "never", "help"])
    assert_that(buf.getvalue(), contains_string("init"))
    assert_that(buf.getvalue(), contains_string("renew-crl"))


def test_pki_stub_warns(capsys: CaptureFixture[str]) -> None:
    with raises(SystemExit):
        main(["--color", "never", "init"])
    err = capsys.readouterr().err
    assert_that(err, contains_string("not implemented"))


def test_unknown_command_exits_nonzero(capsys: CaptureFixture[str]) -> None:
    with raises(SystemExit):
        main(["--color", "never", "bogus"])
    err = capsys.readouterr().err
    assert_that(err, contains_string("Unknown command"))


def test_whitespace_store_exits_cleanly(capsys: CaptureFixture[str]) -> None:
    with raises(SystemExit):
        main(["--color", "never", "--store", " ", "help"])
    err = capsys.readouterr().err
    assert_that(err, contains_string("explicit store"))


def test_prompt_markup_respects_color() -> None:
    from tiny_pki.cli import main as main_mod

    plain = main_mod._prompt_markup(Theme(enabled=False))  # pyright: ignore[reportPrivateUsage]
    assert_that(plain, equal_to("tiny-pki > "))
    colored = main_mod._prompt_markup(Theme(enabled=True))  # pyright: ignore[reportPrivateUsage]
    assert_that(str(colored), contains_string("tiny-pki"))


def test_one_shot_exit_succeeds() -> None:
    main(["--color", "never", "exit"])


def test_repl_history_falls_back(monkeypatch: MonkeyPatch, capsys: CaptureFixture[str]) -> None:
    def boom_history(_path: str) -> InMemoryHistory:
        raise OSError("cannot create history file")

    monkeypatch.setattr(main_mod, "FileHistory", boom_history)
    hist = main_mod._repl_history(Theme(enabled=False))  # pyright: ignore[reportPrivateUsage]
    assert_that(hist, instance_of(InMemoryHistory))
    err = capsys.readouterr().err
    assert_that(err, contains_string("history disabled"))
