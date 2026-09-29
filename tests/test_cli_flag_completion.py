"""Per-command flags drive the parser, help, REPL completion, and shell completion scripts."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from hamcrest import assert_that, contains_inanyorder, contains_string, equal_to, has_item, has_items, is_not
from prompt_toolkit.document import Document
from pytest import CaptureFixture

from tiny_pki.cli.commands import COMMAND_FLAGS, COMMANDS
from tiny_pki.cli.completer import ReplCompleter
from tiny_pki.cli.completion import completion_script
from tiny_pki.cli.main import _argument_tokens, main  # pyright: ignore[reportPrivateUsage]
from tiny_pki.cli.theme import Theme

_BASH = shutil.which("bash")


def _bash_complete(tmp_path: Path, *words: str) -> list[str]:
    """Run the generated bash completer for ``tiny-pki WORDS...`` (the last word is being completed)."""
    assert _BASH is not None
    script = tmp_path / "tiny-pki.bash"
    script.write_text(completion_script("bash"), encoding="utf-8")
    quoted = " ".join("'" + w.replace("'", "'\\''") + "'" for w in ("tiny-pki", *words))
    driver = (
        f"source '{script}'\n"
        f"COMP_WORDS=({quoted})\n"
        f"COMP_CWORD={len(words)}\n"
        "_tiny_pki_completion\n"
        'printf "%s\\n" "${COMPREPLY[@]}"\n'
    )
    result = subprocess.run([_BASH, "--norc", "--noprofile", "-c", driver], capture_output=True, text=True, check=True)
    return [line for line in result.stdout.splitlines() if line]


@pytest.mark.skipif(_BASH is None, reason="bash not installed")
@pytest.mark.parametrize(
    ("words", "expected"),
    [
        (("create", "client", "alice", "--key-t"), ["--key-type"]),
        (("create", "client", "alice", "--key-type", ""), ["rsa", "ec-p256"]),
        (("--store", "/tmp/s", "init", "--key-type", "e"), ["ec-p256"]),
        (("--color", ""), ["auto", "always", "never"]),
        (("create", ""), ["client", "server"]),
        (("revoke", "alice", "--"), ["--dry-run", "--key-secret-file"]),
        (("delete", "--"), ["--force", "--dry-run", "--key-secret-file"]),
        (("check", "--kind", ""), ["ca", "client", "crl", "server"]),
        (("list", "--"), ["--json"]),
        (("completion", ""), ["bash", "fish", "zsh"]),
        (("create", "client", "alice", "--da"), ["--days"]),
        (("list", ""), ["ca", "certs", "clients", "revoked", "servers"]),
        (("show", "c"), ["ca", "certs", "clients", "crl"]),
        (
            ("init", ""),
            [
                "--cn",
                "--crl-days",
                "--days",
                "--encrypt-key",
                "--key-secret-file",
                "--key-size",
                "--key-type",
                "--org",
                "--permit",
            ],
        ),
        (("revoke", "alice", ""), ["--dry-run", "--key-secret-file"]),
        (("list", "--color", ""), ["auto", "always", "never"]),
        (("check", "--edit-mode", "e"), ["emacs"]),
        (("help", "re"), ["renew-crl", "revoke"]),
    ],
)
def test_bash_completes_command_flags_and_values(tmp_path: Path, words: tuple[str, ...], expected: list[str]) -> None:
    assert_that(_bash_complete(tmp_path, *words), contains_inanyorder(*expected))


@pytest.mark.skipif(_BASH is None, reason="bash not installed")
def test_bash_completes_commands_first(tmp_path: Path) -> None:
    assert_that(_bash_complete(tmp_path, "cr"), contains_inanyorder("create", "crl"))
    assert_that(_bash_complete(tmp_path, "--store", "/tmp/s", "re"), contains_inanyorder("renew-crl", "revoke"))


@pytest.mark.skipif(_BASH is None, reason="bash not installed")
def test_bash_completes_paths_for_path_flags_and_positionals(tmp_path: Path) -> None:
    script = completion_script("bash")
    for case in ('"export --out"', '"export --password-file"', '"check --ca"', '"check --crl"'):
        assert_that(script, contains_string(f'{case}) COMPREPLY=( $(compgen -f -- "$cur") )'))
    assert_that(script, contains_string('--store) COMPREPLY=( $(compgen -d -- "$cur") )'))
    (tmp_path / "bundle.p12").write_text("", encoding="utf-8")
    assert_that(_bash_complete(tmp_path, "check", str(tmp_path / "bun")), equal_to([str(tmp_path / "bundle.p12")]))
    assert_that(
        _bash_complete(tmp_path, "export", "--out", str(tmp_path / "bun")), equal_to([str(tmp_path / "bundle.p12")])
    )


@pytest.mark.parametrize("shell", ["bash", "zsh", "fish"])
def test_every_flag_is_in_every_shell_script(shell: str) -> None:
    script = completion_script(shell)
    for cmd, flags in COMMAND_FLAGS.items():
        for flag in flags:
            needle = f"-l {flag.name}" if shell == "fish" else flag.option
            assert_that(script, contains_string(needle), f"{shell}: {cmd} {flag.option}")


@pytest.mark.parametrize(
    ("shell", "needles"),
    [
        (
            "zsh",
            [
                "'--key-type[key algorithm (default rsa)]:TYPE:(rsa ec-p256)'",
                "'--color[",
                "list) _arguments",
                "'--out[output file]:PATH:_files'",
                ":DIR:_files -/'",
            ],
        ),
        (
            "fish",
            [
                "-l key-type -x -a 'rsa ec-p256'",
                "complete -c tiny-pki -l color -x -a 'auto always never'",
                "-l out -r -F",
                "-l store -x -a '(__fish_complete_directories)'",
            ],
        ),
    ],
)
def test_zsh_and_fish_complete_flag_values(shell: str, needles: list[str]) -> None:
    script = completion_script(shell)
    for needle in needles:
        assert_that(script, contains_string(needle))


@pytest.mark.parametrize("shell", ["bash", "zsh", "fish"])
def test_shell_scripts_parse(tmp_path: Path, shell: str) -> None:
    binary = shutil.which(shell)
    if binary is None:
        pytest.skip(f"{shell} not installed")
    script = tmp_path / f"tiny-pki.{shell}"
    script.write_text(completion_script(shell), encoding="utf-8")
    subprocess.run([binary, "-n", str(script)], check=True, capture_output=True)


def _repl(text: str) -> list[str]:
    completer = ReplCompleter(commands=COMMANDS, theme=Theme(enabled=False))
    return [c.text for c in completer.get_completions(Document(text, len(text)), None)]


def test_repl_completes_flags_and_values() -> None:
    assert_that(
        _repl("create client alice --ke"),
        contains_inanyorder("--keep-previous", "--key-secret-file", "--key-size", "--key-type"),
    )
    assert_that(_repl("create client alice --key-type "), contains_inanyorder("rsa", "ec-p256"))
    assert_that(_repl("init --key-size 3"), equal_to(["3072"]))
    assert_that(_repl("revoke alice --"), contains_inanyorder("--dry-run", "--key-secret-file"))


def test_repl_completes_positional_choices_from_the_table() -> None:
    completer = ReplCompleter(
        commands=COMMANDS, theme=Theme(enabled=False), argument_tokens=lambda c: _argument_tokens(c, None)
    )
    offered = [c.text for c in completer.get_completions(Document("completion ", 11), None)]
    assert_that(offered, has_items("bash", "fish", "zsh"))


def test_repl_completes_command_names_after_help() -> None:
    completer = ReplCompleter(
        commands=COMMANDS, theme=Theme(enabled=False), argument_tokens=lambda c: _argument_tokens(c, None)
    )
    offered = [c.text for c in completer.get_completions(Document("help re", 7), None)]
    assert_that(offered, contains_inanyorder("renew-crl", "revoke"))


def test_repl_offers_flags_after_a_space() -> None:
    assert_that(_repl("init "), has_item("--key-type"))
    assert_that(_repl("revoke alice "), has_item("--dry-run"))
    assert_that(_repl("revoke alice --dry-run "), is_not(has_item("--dry-run")))


def test_repl_does_not_reoffer_used_flags_unless_repeatable() -> None:
    offered = _repl("create server api --yes --san a --")
    assert_that(offered, has_item("--san"))
    assert_that(offered, is_not(has_item("--yes")))


def test_help_command_lists_usage_and_flags(capsys: CaptureFixture[str]) -> None:
    main(["--color", "never", "help", "create"])
    out = capsys.readouterr().out
    assert_that(out, contains_string("usage: create client|server NAME [options]"))
    assert_that(out, contains_string("--key-type rsa|ec-p256"))
    assert_that(out, contains_string("--keep-previous"))
    main(["--color", "never", "help"])
    assert_that(capsys.readouterr().out, contains_string("help <command>"))


def test_help_for_each_command_lists_all_its_flags(capsys: CaptureFixture[str]) -> None:
    for cmd in COMMANDS:
        main(["--color", "never", "help", cmd])
        out = capsys.readouterr().out
        assert_that(out, contains_string("usage: "))
        if COMMAND_FLAGS.get(cmd):
            assert_that(out, contains_string("options:"))
        for flag in COMMAND_FLAGS.get(cmd, ()):
            assert_that(out, contains_string(flag.option))


def test_help_for_unknown_command_fails(capsys: CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as raised:
        main(["--color", "never", "help", "frobnicate"])
    assert_that(raised.value.code, equal_to(1))
    assert_that(capsys.readouterr().err, contains_string("Unknown command 'frobnicate'"))
