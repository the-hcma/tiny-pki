"""PKI command handlers for the tiny-pki REPL.

Shell chrome lives in ``main``; this module implements init/create/show/…
"""

from __future__ import annotations

import getpass
import json
import os
import sys
import warnings
from datetime import UTC, datetime
from pathlib import Path
from typing import TypedDict

from tiny_pki import (
    DEFAULT_CA_KEY_SIZE,
    DEFAULT_CA_VALIDITY_DAYS,
    DEFAULT_CLIENT_VALIDITY_DAYS,
    DEFAULT_LEAF_KEY_SIZE,
    DEFAULT_ORGANIZATION_NAME,
    DEFAULT_SERVER_VALIDITY_DAYS,
    TinyPkiWarning,
    generate_ca_certificate,
    generate_client_certificate,
    generate_crl,
    generate_pkcs12,
    generate_server_certificate,
    get_certificate_expiry,
    get_certificate_fingerprint,
    get_certificate_issuer,
    get_certificate_sans,
    get_certificate_serial_number,
    get_certificate_subject,
)
from tiny_pki.cli.theme import Theme
from tiny_pki.names import common_name_as_san, normalize_san_entries
from tiny_pki.store import CertificateStore, IssuedCertificate


class HandlerNotReadyError(RuntimeError):
    """Kept for the shell dispatch contract; not raised by real handlers."""


class _ParsedFlags(TypedDict):
    positional: list[str]
    flags: dict[str, str]
    multi: dict[str, list[str]]


def dispatch(
    command: str,
    args: list[str],
    *,
    store: CertificateStore | None,
    theme: Theme,
) -> None:
    """Dispatch a PKI verb. Raises ValueError/KeyError/FileNotFoundError on user errors."""
    if command == "renew-crl":
        command = "crl"
    handlers = {
        "create": _cmd_create,
        "crl": _cmd_crl,
        "delete": _cmd_delete,
        "export": _cmd_export,
        "init": _cmd_init,
        "inspect": _cmd_inspect,
        "list": _cmd_list,
        "revoke": _cmd_revoke,
        "show": _cmd_show,
    }
    handler = handlers.get(command)
    if handler is None:
        raise ValueError(f"Unknown command {command!r}; type help")
    handler(args, store=store, theme=theme)


def _confirm_cn_in_sans(name: str, sans: list[str], flags: dict[str, str]) -> bool:
    """Decide whether a host-like CN missing from ``--san`` should be added.

    ``--no-cn-san`` declines, ``--yes`` or a non-interactive stdin accepts (the
    library then warns), otherwise the operator is asked.
    """
    if "no-cn-san" in flags:
        return False
    cn_san = common_name_as_san(name)
    if cn_san is None or cn_san in normalize_san_entries(sans):
        return True
    if "yes" in flags or not sys.stdin.isatty():
        return True
    try:
        answer = input(f"CN {name!r} is not in --san; clients ignore the CN. Add it as a SAN? [Y/n] ")
    except (EOFError, KeyboardInterrupt) as exc:
        raise ValueError("Expected an answer to the CN-in-SAN prompt; pass --yes or --no-cn-san") from exc
    return answer.strip().lower() in {"", "y", "yes"}


def _require_store(store: CertificateStore | None) -> CertificateStore:
    if store is None:
        raise ValueError("Expected --store / TINY_PKI_STORE for this command")
    return store


def _cmd_init(args: list[str], *, store: CertificateStore | None, theme: Theme) -> None:
    store = _require_store(store)
    opts = _parse_flags(args, allowed={"cn", "days", "key-size", "org", "permit"})
    if opts["positional"]:
        raise ValueError("init takes no positional arguments; use --cn / --org")
    if store.has_ca():
        raise ValueError(f"CA already exists under {store.root}")
    cn = opts["flags"].get("cn", "Private CA")
    org = opts["flags"].get("org", DEFAULT_ORGANIZATION_NAME)
    days = _parse_days(opts["flags"].get("days", str(DEFAULT_CA_VALIDITY_DAYS)), default=DEFAULT_CA_VALIDITY_DAYS)
    key_size = int(opts["flags"].get("key-size", str(DEFAULT_CA_KEY_SIZE)))
    cert_pem, key_pem = generate_ca_certificate(
        cn,
        organization_name=org,
        validity_days=days,
        key_size=key_size,
        permitted_subtrees=opts["multi"].get("permit"),
    )
    store.write_ca(cert_pem, key_pem)
    store.write_crl(generate_crl(cert_pem, key_pem, []))
    print(theme.ok(f"CA created: {get_certificate_subject(cert_pem)}"))
    print(theme.dim(f"fingerprint {get_certificate_fingerprint(cert_pem)}"))


def _cmd_create(args: list[str], *, store: CertificateStore | None, theme: Theme) -> None:
    store = _require_store(store)
    if not args:
        raise ValueError("Expected create client|server <name>")
    kind = args[0]
    opts = _parse_flags(args[1:], allowed={"allow-long-validity", "days", "key-size", "no-cn-san", "org", "san", "yes"})
    positional = opts["positional"]
    if kind not in {"client", "server"}:
        raise ValueError(f"Expected create client|server, got {kind!r}")
    if not positional:
        raise ValueError(f"Expected identity/common name after create {kind}")
    name = positional[0]
    if len(positional) > 1:
        raise ValueError("Unexpected extra arguments")
    if kind == "client" and (opts["multi"].get("san") or {"no-cn-san", "yes"} & opts["flags"].keys()):
        raise ValueError("--san / --no-cn-san / --yes are only supported for server certificates")
    if "no-cn-san" in opts["flags"] and not opts["multi"].get("san"):
        raise ValueError("Expected --san with --no-cn-san; without --san the CN is the only SAN")
    ca_cert, ca_key = store.read_ca()
    default_days = DEFAULT_CLIENT_VALIDITY_DAYS if kind == "client" else DEFAULT_SERVER_VALIDITY_DAYS
    days = _parse_days(opts["flags"].get("days", str(default_days)), default=default_days)
    key_size = int(opts["flags"].get("key-size", str(DEFAULT_LEAF_KEY_SIZE)))
    org = opts["flags"].get("org")
    allow_long_validity = "allow-long-validity" in opts["flags"]

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", TinyPkiWarning)
        if kind == "client":
            cert_pem, key_pem = generate_client_certificate(
                ca_cert,
                ca_key,
                name,
                organization_name=org,
                validity_days=days,
                key_size=key_size,
                allow_long_validity=allow_long_validity,
            )
        else:
            sans = [s for s in opts["multi"].get("san", []) if s] or [name]
            cert_pem, key_pem = generate_server_certificate(
                ca_cert,
                ca_key,
                name,
                sans,
                organization_name=org,
                validity_days=days,
                key_size=key_size,
                allow_long_validity=allow_long_validity,
                include_common_name_in_sans=_confirm_cn_in_sans(name, sans, opts["flags"]),
            )
    for warning in caught:
        print(theme.warn(f"warning: {warning.message}"), file=sys.stderr)

    entry = store.add_certificate(
        common_name=name,
        kind=kind,  # type: ignore[arg-type]
        serial_number=get_certificate_serial_number(cert_pem),
        cert_pem=cert_pem,
        key_pem=key_pem,
        not_valid_after=get_certificate_expiry(cert_pem),
        fingerprint=get_certificate_fingerprint(cert_pem),
    )
    # Re-issue may auto-revoke a prior live CN — keep crl.pem aligned with the index.
    store.write_crl(generate_crl(ca_cert, ca_key, store.revoked_entries()))
    print(theme.ok(f"issued {kind} {entry.common_name}"))
    print(theme.dim(f"serial {entry.serial_number}  fp {entry.fingerprint}"))


def _cmd_show(args: list[str], *, store: CertificateStore | None, theme: Theme) -> None:
    store = _require_store(store)
    target = args[0] if args else "certs"
    if target in {"ca", "certs", "clients", "servers", "revoked"}:
        _cmd_list([target, *args[1:]], store=store, theme=theme)
        return
    if target == "crl":
        crl = store.read_crl()
        if crl is None:
            print(theme.dim("(no crl.pem yet)"))
            return
        print(theme.dim(f"{store.crl_path} ({len(crl)} bytes)"))
        for serial, when in store.revoked_entries():
            print(f"  revoked serial={format(serial, 'x')} at {when.isoformat()}")
        return
    entry = store.get_certificate(target)
    if entry is None:
        raise KeyError(f"Expected issued certificate matching {target!r}")
    cert_pem = store.read_certificate_pem(entry)
    _print_cert_summary(cert_pem, theme)
    if entry.revoked_at:
        print(theme.error(f"revoked_at {entry.revoked_at}"))


def _cmd_list(args: list[str], *, store: CertificateStore | None, theme: Theme) -> None:
    store = _require_store(store)
    as_json = "--json" in args
    positional = [a for a in args if a != "--json"]
    target = positional[0] if positional else ""

    if target in {"", "summary"}:
        _list_summary(store, theme=theme, as_json=as_json)
        return
    if target == "ca":
        _list_ca(store, theme=theme, as_json=as_json)
        return
    if target == "clients":
        _print_entry_list(
            store.list_certificates(kind="client", status="active"),
            store=store,
            theme=theme,
            as_json=as_json,
        )
        return
    if target == "servers":
        _print_entry_list(
            store.list_certificates(kind="server", status="active"),
            store=store,
            theme=theme,
            as_json=as_json,
        )
        return
    if target == "revoked":
        _print_entry_list(
            store.list_certificates(status="revoked"),
            store=store,
            theme=theme,
            as_json=as_json,
        )
        return
    if target == "certs":
        _print_entry_list(
            store.list_certificates(status="all"),
            store=store,
            theme=theme,
            as_json=as_json,
        )
        return
    raise ValueError(f"Expected list ca|clients|servers|revoked|certs, got {target!r}")


def _list_ca(store: CertificateStore, *, theme: Theme, as_json: bool) -> None:
    ca_cert, _ = store.read_ca()
    if as_json:
        print(
            json.dumps(
                {
                    "cn": get_certificate_subject(ca_cert),
                    "fingerprint": get_certificate_fingerprint(ca_cert),
                    "expires": get_certificate_expiry(ca_cert).isoformat(),
                    "cert_path": str(store.ca_cert_path),
                    "crl_path": str(store.crl_path),
                    "index_path": str(store.index_path),
                },
                sort_keys=True,
            )
        )
        return
    _print_cert_summary(ca_cert, theme)
    print(theme.dim(f"cert {store.ca_cert_path}"))
    print(theme.dim(f"crl  {store.crl_path}"))
    print(theme.dim(f"index {store.index_path}"))


def _list_summary(store: CertificateStore, *, theme: Theme, as_json: bool) -> None:
    clients = store.list_certificates(kind="client", status="active")
    servers = store.list_certificates(kind="server", status="active")
    revoked = store.list_certificates(status="revoked")
    ca_cn = get_certificate_subject(store.read_ca()[0]) if store.has_ca() else None
    if as_json:
        print(
            json.dumps(
                {
                    "ca_cn": ca_cn,
                    "clients": len(clients),
                    "servers": len(servers),
                    "revoked": len(revoked),
                    "store": str(store.root),
                },
                sort_keys=True,
            )
        )
        return
    if ca_cn is None:
        print(theme.dim("(no CA)"))
    else:
        print(theme.ok(f"CA {ca_cn}"))
    print(theme.dim(f"clients {len(clients)}  servers {len(servers)}  revoked {len(revoked)}"))
    print(theme.dim(f"store {store.root}"))


def _print_entry_list(
    entries: list[IssuedCertificate],
    *,
    store: CertificateStore,
    theme: Theme,
    as_json: bool,
) -> None:
    if as_json:
        rows = [
            {
                "cn": e.common_name,
                "kind": e.kind,
                "serial": e.serial_number,
                "fingerprint": e.fingerprint,
                "expires": e.not_valid_after,
                "status": "revoked" if e.revoked_at else "active",
                "revoked_at": e.revoked_at,
                "cert_path": str(store.root / e.cert_path) if e.cert_path else "",
                "key_path": str(store.root / e.key_path) if e.key_path else "",
                "store": str(store.root),
            }
            for e in entries
        ]
        print(json.dumps(rows, sort_keys=True))
        return
    if not entries:
        print(theme.dim("(none)"))
        return
    for entry in entries:
        status = "revoked" if entry.revoked_at else "active"
        color = theme.error if entry.revoked_at else theme.ok
        print(
            f"{color(status)}  {entry.kind:6}  {entry.common_name}  "
            f"serial={entry.serial_number}  expires={entry.not_valid_after}"
        )


def _cmd_inspect(args: list[str], *, store: CertificateStore | None, theme: Theme) -> None:
    if not args:
        raise ValueError("Expected inspect <identity|path>")
    target = args[0]
    path = Path(target)
    if path.is_file():
        _print_cert_summary(path.read_bytes(), theme)
        return
    store = _require_store(store)
    entry = store.get_certificate(target)
    if entry is None:
        raise KeyError(f"Expected PEM path or store identity, got {target!r}")
    _print_cert_summary(store.read_certificate_pem(entry), theme)


def _cmd_revoke(args: list[str], *, store: CertificateStore | None, theme: Theme) -> None:
    store = _require_store(store)
    if not args:
        raise ValueError("Expected revoke <identity|serial>")
    target = store.get_certificate(args[0])
    if target is None:
        raise KeyError(f"Expected issued certificate matching {args[0]!r}")
    entry = store.mark_revoked(target.serial_number)
    ca_cert, ca_key = store.read_ca()
    store.write_crl(generate_crl(ca_cert, ca_key, store.revoked_entries()))
    print(theme.warn(f"revoked {entry.common_name}"))
    print(theme.dim(f"crl updated: {store.crl_path}"))


def _cmd_delete(args: list[str], *, store: CertificateStore | None, theme: Theme) -> None:
    store = _require_store(store)
    opts = _parse_flags(args, allowed={"force"})
    if not opts["positional"]:
        raise ValueError("Expected delete <identity|serial> [--force]")
    force = "--force" in args or "force" in opts["flags"]
    entry = store.delete_certificate(opts["positional"][0], force=force)
    # Keep crl.pem aligned with tombstones / remaining revoked serials.
    if store.has_ca():
        ca_cert, ca_key = store.read_ca()
        store.write_crl(generate_crl(ca_cert, ca_key, store.revoked_entries()))
    print(theme.ok(f"deleted {entry.common_name}"))


def _cmd_export(args: list[str], *, store: CertificateStore | None, theme: Theme) -> None:
    store = _require_store(store)
    if len(args) < 2:
        raise ValueError("Expected export pem|p12 <identity> [--out PATH] [--legacy] [--password-file PATH]")
    fmt = args[0]
    opts = _parse_flags(args[1:], allowed={"legacy", "out", "password-file"})
    if not opts["positional"]:
        raise ValueError("Expected identity after export format")
    identity = opts["positional"][0]
    entry = store.get_certificate(identity)
    if entry is None:
        raise KeyError(f"Expected issued certificate matching {identity!r}")
    cert_pem = store.read_certificate_pem(entry)
    key_pem = store.read_key_pem(entry)
    ca_cert, _ = store.read_ca()

    if fmt == "pem":
        out = Path(opts["flags"].get("out", f"{entry.common_name}.pem"))
        _write_secret_file(out, cert_pem.decode() + key_pem.decode())
        print(theme.ok(f"wrote {out}"))
        return
    if fmt == "p12":
        password_file = opts["flags"].get("password-file")
        password = _read_password_file(Path(password_file)) if password_file else _prompt_p12_password()
        p12 = generate_pkcs12(
            cert_pem, key_pem, ca_cert, entry.common_name, password.encode(), legacy="legacy" in opts["flags"]
        )
        out_flag = opts["flags"].get("out")
        if out_flag:
            path = Path(out_flag)
            _write_secret_file(path, p12)
        else:
            path = store.write_bundle(entry.common_name, p12, serial_number=entry.serial_number)
        print(theme.ok(f"wrote {path}"))
        if password_file:
            _offer_to_remove_password_file(Path(password_file), theme)
        return
    raise ValueError(f"Expected export pem|p12, got {fmt!r}")


def _offer_to_remove_password_file(path: Path, theme: Theme) -> None:
    """Warn that ``path`` holds the bundle password in plaintext and offer to delete it."""
    print(theme.warn(f"warning: {path} holds the bundle password in plaintext"), file=sys.stderr)
    remove = False
    if sys.stdin.isatty():
        try:
            answer = input(f"Remove {path} now? [Y/n] ")
        except (EOFError, KeyboardInterrupt):
            answer = "n"
        remove = answer.strip().lower() in {"", "y", "yes"}
    if remove:
        path.unlink(missing_ok=True)
        print(theme.ok(f"removed {path}"))
    else:
        print(theme.warn(f"warning: left {path} in place; delete it once the device has the bundle"), file=sys.stderr)


def _prompt_p12_password() -> str:
    try:
        password = getpass.getpass("PKCS#12 password: ")
        if password and getpass.getpass("Repeat password: ") != password:
            raise ValueError("Expected the repeated password to match")
    except (EOFError, KeyboardInterrupt) as exc:
        raise ValueError("Expected a non-empty password") from exc
    if not password:
        raise ValueError("Expected a non-empty password")
    return password


def _read_password_file(path: Path) -> str:
    """Read the first line of ``path`` (trailing newline dropped) as the bundle password."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Expected a readable --password-file, got {path} ({exc.strerror})") from exc
    except UnicodeDecodeError as exc:
        raise ValueError(f"Expected a UTF-8 --password-file, got undecodable bytes in {path}") from exc
    lines = text.splitlines()
    password = lines[0] if lines else ""
    if not password:
        raise ValueError(f"Expected a password on the first line of {path}, got an empty line")
    return password


def _cmd_crl(args: list[str], *, store: CertificateStore | None, theme: Theme) -> None:
    del args
    store = _require_store(store)
    ca_cert, ca_key = store.read_ca()
    store.write_crl(generate_crl(ca_cert, ca_key, store.revoked_entries()))
    print(theme.ok(f"crl regenerated: {store.crl_path}"))


def _print_cert_summary(cert_pem: bytes, theme: Theme) -> None:
    expiry = get_certificate_expiry(cert_pem)
    now = datetime.now(UTC)
    if expiry <= now:
        status = theme.error("expired")
    elif (expiry - now).days <= 30:
        status = theme.warn("expiring soon")
    else:
        status = theme.ok("valid")
    print(f"subject   {get_certificate_subject(cert_pem)}")
    print(f"issuer    {get_certificate_issuer(cert_pem)}")
    print(f"serial    {format(get_certificate_serial_number(cert_pem), 'x')}")
    print(f"expires   {expiry.isoformat()} ({status})")
    print(f"fingerprint {get_certificate_fingerprint(cert_pem)}")
    sans = get_certificate_sans(cert_pem)
    if sans:
        print(f"sans      {', '.join(sans)}")


def _parse_days(raw: str, *, default: int) -> int:
    """Parse ``--days`` into a positive int that cannot overflow datetime math."""
    text = raw.strip() if raw else str(default)
    if not text:
        raise ValueError("Expected a positive integer for --days")
    try:
        days = int(text)
    except ValueError as exc:
        raise ValueError(f"Expected a positive integer for --days, got {raw!r}") from exc
    if days < 1 or days > 36500:
        raise ValueError(f"Expected --days between 1 and 36500, got {days}")
    return days


def _parse_flags(args: list[str], *, allowed: set[str]) -> _ParsedFlags:
    """Parse ``--flag value`` / ``--flag`` and collect positionals.

    Repeated ``--san`` / ``--permit`` accumulate in ``multi``. Value-less flags (``--force``)
    never consume the following positional token.
    """
    positional: list[str] = []
    flags: dict[str, str] = {}
    multi: dict[str, list[str]] = {}
    valueless = frozenset({"allow-long-validity", "force", "legacy", "no-cn-san", "yes"})
    i = 0
    while i < len(args):
        token = args[i]
        if token.startswith("--"):
            name = token[2:]
            if name not in allowed:
                raise ValueError(f"Unknown flag --{name}")
            if name in valueless:
                value = ""
                i += 1
            elif i + 1 < len(args) and not args[i + 1].startswith("--"):
                value = args[i + 1]
                i += 2
            else:
                value = ""
                i += 1
            if not value and name in {"out", "password-file", "permit", "san"}:
                raise ValueError(f"Expected a non-empty value for --{name}")
            if name in {"permit", "san"}:
                multi.setdefault(name, []).append(value)
            else:
                flags[name] = value
            continue
        positional.append(token)
        i += 1
    return {"positional": positional, "flags": flags, "multi": multi}


def _write_secret_file(path: Path, data: str | bytes) -> None:
    """Write bytes/text with mode 0600 from creation (no world-readable window)."""
    payload = data.encode() if isinstance(data, str) else data
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError(f"Expected progress writing {path}, got {written} bytes")
            view = view[written:]
    finally:
        os.close(fd)
    os.chmod(path, 0o600)
