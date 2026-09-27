"""Shell completion script generation and optional per-user install."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import NoReturn

from tiny_pki.cli.commands import COMMAND_FLAGS, COMMAND_HELP, COMMANDS, POSITIONAL_CHOICES, Flag

_PROG = "tiny-pki"
_SHELLS = frozenset({"bash", "fish", "zsh"})
_TOP_FLAGS = (
    Flag("color", "colour output", value="WHEN", choices=("auto", "always", "never")),
    Flag("edit-mode", "REPL key bindings", value="MODE", choices=POSITIONAL_CHOICES["edit-mode"]),
    Flag("help", "show launcher help"),
    Flag("store", "store directory (or TINY_PKI_STORE)", value="DIR", path=True),
    Flag("version", "print the version and exit"),
)
# Commands whose positional arguments are file paths.
_PATH_POSITIONALS = frozenset({"check", "inspect"})


def completion_install_path(shell: str) -> Path:
    """Conventional per-user path for a shell's tiny-pki completion script."""
    xdg_data = _xdg_base("XDG_DATA_HOME", Path.home() / ".local" / "share")
    if shell == "bash":
        return xdg_data / "bash-completion" / "completions" / "tiny-pki.bash"
    if shell == "fish":
        xdg_config = _xdg_base("XDG_CONFIG_HOME", Path.home() / ".config")
        return xdg_config / "fish" / "completions" / "tiny-pki.fish"
    return xdg_data / "zsh" / "site-functions" / "_tiny-pki"


def completion_script(shell: str) -> str:
    """Return a tab-completion script for ``bash``, ``zsh``, or ``fish``."""
    if shell == "bash":
        return _bash_script()
    if shell == "fish":
        return _fish_script()
    if shell == "zsh":
        return _zsh_script()
    raise ValueError(f"unsupported shell: {shell!r} (expected bash, zsh, or fish)")


def run_completion(argv: list[str]) -> int:
    """Handle ``tiny-pki completion <shell> [--install] [--force] [--json]``.

    Returns 0 on success, 2 on usage errors, 1 on install I/O failures.
    """
    try:
        shell, install, force, as_json = _parse_completion_argv(argv)
    except SystemExit as exc:
        code = exc.code
        return int(code) if isinstance(code, int) else 2
    if force and not install:
        _emit_error(
            message="--force only applies with --install",
            as_json=as_json,
            hint="Pass --install, or drop --force.",
        )
        return 2

    script = completion_script(shell)
    if not script.endswith("\n"):
        script += "\n"

    if not install:
        if as_json:
            print(json.dumps({"shell": shell, "script": script}, sort_keys=True))
        else:
            sys.stdout.write(script)
        return 0

    path = completion_install_path(shell)
    want = script.encode()

    def _refuse_clobber() -> NoReturn:
        _emit_error(
            message=f"{path} already exists with different contents",
            as_json=as_json,
            hint="Re-run with --force to overwrite it.",
        )
        raise SystemExit(2)

    try:
        # Refuse symlinks (including dangling) so --force cannot rewrite a
        # link target outside the conventional install path.
        if path.is_symlink() or (path.exists() and not path.is_file()):
            _emit_error(
                message=f"{path} exists but is not a regular file",
                as_json=as_json,
                hint="Remove it (or point XDG_DATA_HOME/XDG_CONFIG_HOME elsewhere), then retry.",
            )
            return 1
        current = path.read_bytes() if path.is_file() else None
        if current == want:
            action = "unchanged"
        elif current is not None and not force:
            _refuse_clobber()
        elif force:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(want)
            action = "written"
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                with path.open("xb") as handle:
                    handle.write(want)
                action = "written"
            except FileExistsError:
                if path.read_bytes() != want:
                    _refuse_clobber()
                action = "unchanged"
    except SystemExit as exc:
        code = exc.code
        return int(code) if isinstance(code, int) else 2
    except OSError as exc:
        _emit_error(
            message=f"could not install the completion script to {path}: {exc}",
            as_json=as_json,
            hint="Ensure the path is a writable file (not a directory) that you own.",
        )
        return 1

    if as_json:
        print(json.dumps({"action": action, "path": str(path), "shell": shell}, sort_keys=True))
    else:
        lines = [f"{action}: {path}"]
        if shell == "zsh":
            lines.append(
                f"  ensure {path.parent} is on $fpath before `compinit` (e.g. in ~/.zshrc), then open a new shell"
            )
        else:
            lines.append("  open a new shell to pick it up")
        print("\n".join(lines))
    return 0


def _bash_script() -> str:
    value_flags = " ".join(f.option for f in _TOP_FLAGS if f.value is not None)
    top = " ".join(f.option for f in _TOP_FLAGS)
    top_values = "\n".join(f"      {f.option}) {_bash_values(f)}; return ;;" for f in _TOP_FLAGS if f.value is not None)
    value_cases = [f'    *" {f.option}") {_bash_values(f)}; return ;;' for f in _TOP_FLAGS if f.value is not None]
    flag_cases: list[str] = []
    positional_cases: list[str] = []
    for cmd in COMMANDS:
        flags = COMMAND_FLAGS.get(cmd, ())
        for flag in flags:
            if flag.value is not None:
                value_cases.append(f'    "{cmd} {flag.option}") {_bash_values(flag)}; return ;;')
        if flags:
            flag_cases.append(
                f'      {cmd}) COMPREPLY=( $(compgen -W "{" ".join(f.option for f in flags)}" -- "$cur") ) ;;'
            )
        if cmd in _PATH_POSITIONALS:
            positional_cases.append(f'    {cmd}) COMPREPLY=( $(compgen -f -- "$cur") ) ;;')
        elif cmd in POSITIONAL_CHOICES:
            words = " ".join(POSITIONAL_CHOICES[cmd])
            positional_cases.append(
                f'    {cmd}) [[ "$prev" == "$cmd" ]] && COMPREPLY=( $(compgen -W "{words}" -- "$cur") ) ;;'
            )
    nl = "\n"
    return f"""# tiny-pki bash completion — generated by `tiny-pki completion bash`
_tiny_pki_completion() {{
  local cur prev cmd="" i word
  COMPREPLY=()
  cur="${{COMP_WORDS[COMP_CWORD]}}"
  prev="${{COMP_WORDS[COMP_CWORD-1]}}"
  for (( i = 1; i < COMP_CWORD; i++ )); do
    word="${{COMP_WORDS[i]}}"
    case " {value_flags} " in
      *" $word "*) (( i++ )); continue ;;
    esac
    [[ "$word" == -* ]] && continue
    cmd="$word"
    break
  done
  if [[ -z "$cmd" ]]; then
    case "$prev" in
{top_values}
    esac
    COMPREPLY=( $(compgen -W "{" ".join(COMMANDS)} {top}" -- "$cur") )
    return
  fi
  case "$cmd $prev" in
{nl.join(value_cases)}
  esac
  if [[ "$cur" != -* ]]; then
    case "$cmd" in
{nl.join(positional_cases)}
    esac
    (( ${{#COMPREPLY[@]}} )) && return
  fi
  case "$cmd" in
{nl.join(flag_cases)}
  esac
}}
complete -F _tiny_pki_completion {_PROG}
"""


def _bash_values(flag: Flag) -> str:
    """The ``COMPREPLY=...`` assignment for a flag's value."""
    if flag.choices:
        return f'COMPREPLY=( $(compgen -W "{" ".join(flag.choices)}" -- "$cur") )'
    if flag.name == "store":
        return 'COMPREPLY=( $(compgen -d -- "$cur") )'
    if flag.path:
        return 'COMPREPLY=( $(compgen -f -- "$cur") )'
    return "COMPREPLY=()"


def _emit_error(*, message: str, as_json: bool, hint: str | None = None) -> None:
    if as_json:
        payload: dict[str, object] = {"error": "usage_error", "message": message, "ok": False}
        if hint:
            payload["hint"] = hint
        if "not a regular file" in message or "could not install" in message:
            payload["error"] = "install_failed"
        print(json.dumps(payload, sort_keys=True), file=sys.stderr)
        return
    print(message, file=sys.stderr)
    if hint:
        print(hint, file=sys.stderr)


def _fish_script() -> str:
    lines = [
        "# tiny-pki fish completion — generated by `tiny-pki completion fish`",
        f"complete -c {_PROG} -f",
    ]
    for flag in _TOP_FLAGS:
        condition = "" if flag.value is not None else "-n __fish_use_subcommand "
        lines.append(f"complete -c {_PROG} {condition}{_fish_flag(flag)}")
    descriptions = dict(COMMAND_HELP)
    for cmd in COMMANDS:
        lines.append(f"complete -c {_PROG} -n __fish_use_subcommand -a {cmd} -d {_sq(descriptions[cmd])}")
    for cmd in COMMANDS:
        seen = _sq(f"__fish_seen_subcommand_from {cmd}")
        if cmd in _PATH_POSITIONALS:
            lines.append(f"complete -c {_PROG} -n {seen} -F")
        elif cmd in POSITIONAL_CHOICES:
            lines.append(f"complete -c {_PROG} -n {seen} -a {_sq(' '.join(POSITIONAL_CHOICES[cmd]))}")
        for flag in COMMAND_FLAGS.get(cmd, ()):
            lines.append(f"complete -c {_PROG} -n {seen} {_fish_flag(flag)}")
    return "\n".join(lines) + "\n"


def _fish_flag(flag: Flag) -> str:
    parts = [f"-l {flag.name}"]
    if flag.choices:
        parts.append(f"-x -a {_sq(' '.join(flag.choices))}")
    elif flag.name == "store":
        parts.append("-x -a '(__fish_complete_directories)'")
    elif flag.path:
        parts.append("-r -F")
    elif flag.value is not None:
        parts.append("-x")
    parts.append(f"-d {_sq(flag.help)}")
    return " ".join(parts)


def _parse_completion_argv(argv: list[str]) -> tuple[str, bool, bool, bool]:
    if not argv:
        print(
            "usage: tiny-pki completion <bash|zsh|fish> [--install] [--force] [--json]",
            file=sys.stderr,
        )
        raise SystemExit(2)
    shell = argv[0]
    if shell not in _SHELLS:
        print(f"unsupported shell: {shell!r} (expected bash, zsh, or fish)", file=sys.stderr)
        raise SystemExit(2)
    install = False
    force = False
    as_json = False
    for token in argv[1:]:
        if token == "--install":
            install = True
        elif token == "--force":
            force = True
        elif token == "--json":
            as_json = True
        else:
            print(f"unexpected argument: {token!r}", file=sys.stderr)
            raise SystemExit(2)
    return shell, install, force, as_json


def _xdg_base(var: str, default: Path) -> Path:
    """XDG base dir from ``$var``, honoring the spec: a relative value is ignored."""
    value = os.environ.get(var, "")
    candidate = Path(value) if value else default
    return candidate if candidate.is_absolute() else default


def _zsh_script() -> str:
    descriptions = dict(COMMAND_HELP)
    cmds = "\n    ".join(_sq(f"{cmd.replace(':', '\\:')}:{descriptions[cmd]}") for cmd in COMMANDS)
    top = " \\\n    ".join(_zsh_spec(flag) for flag in _TOP_FLAGS)
    global_specs = [_zsh_spec(flag) for flag in _TOP_FLAGS if flag.value is not None]
    cases: list[str] = []
    for cmd in COMMANDS:
        specs = [_zsh_spec(flag) for flag in COMMAND_FLAGS.get(cmd, ())] + global_specs
        if cmd in _PATH_POSITIONALS:
            specs.append("'*:file:_files'")
        elif cmd == "export":
            specs.extend(["'1:format:(p12 pem)'", "'2:name: '"])
        elif cmd in POSITIONAL_CHOICES:
            specs.append(_sq(f"1:argument:({' '.join(POSITIONAL_CHOICES[cmd])})"))
        cases.append(f"        {cmd}) _arguments {' '.join(specs)} ;;")
    body = "\n".join(cases)
    # Function name must match the installed file (``_tiny-pki``) so zsh
    # autoload from ``$fpath`` finds the right completer without a second
    # ``compdef`` call.
    return f"""#compdef {_PROG}
# tiny-pki zsh completion — generated by `tiny-pki completion zsh`
_tiny-pki() {{
  local -a cmds
  cmds=(
    {cmds}
  )
  local context state state_descr line
  typeset -A opt_args
  _arguments -C \\
    {top} \\
    '1:command:->cmd' \\
    '*::arg:->args'
  case $state in
    cmd)
      _describe -t commands 'tiny-pki command' cmds
      ;;
    args)
      case $words[1] in
{body}
      esac
      ;;
  esac
}}
"""


def _zsh_spec(flag: Flag) -> str:
    """An ``_arguments`` option spec such as ``'--key-type[key algorithm]:TYPE:(rsa ec-p256)'``."""
    text = flag.help.replace("\\", "\\\\").replace("[", "\\[").replace("]", "\\]")
    prefix = "*" if flag.repeatable else ""
    spec = f"{prefix}{flag.option}[{text}]"
    if flag.value is not None:
        if flag.choices:
            action = f"({' '.join(flag.choices)})"
        elif flag.name == "store":
            action = "_files -/"
        elif flag.path:
            action = "_files"
        else:
            action = " "
        spec += f":{flag.value}:{action}"
    elif flag.name in {"help", "version"}:
        spec = f"(- *){spec}"
    return _sq(spec)


def _sq(text: str) -> str:
    """Quote ``text`` as one single-quoted shell word."""
    return "'" + text.replace("'", "'\\''") + "'"
