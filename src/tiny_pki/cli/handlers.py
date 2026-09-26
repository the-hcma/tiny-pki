"""PKI command handlers for the tiny-pki REPL.

Shell chrome lives in ``main``; this module implements init/create/show/…
"""

from __future__ import annotations

import getpass
import json
import sys
import warnings
from collections import Counter
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, date, datetime, time, timedelta
from pathlib import Path
from typing import TypedDict

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from tiny_pki import (
    DEFAULT_CA_KEY_SIZE,
    DEFAULT_CA_VALIDITY_DAYS,
    DEFAULT_CLIENT_VALIDITY_DAYS,
    DEFAULT_LEAF_KEY_SIZE,
    DEFAULT_ORGANIZATION_NAME,
    DEFAULT_SERVER_VALIDITY_DAYS,
    MAX_VALIDITY_DAYS,
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
from tiny_pki._fsutil import write_file_atomic
from tiny_pki.check import CertificateStatus, Status, check_certificate, check_crl, worst_status
from tiny_pki.cli.theme import Theme
from tiny_pki.names import common_name_as_san, normalize_san_entries
from tiny_pki.store import CertificateStore, IssuedCertificate

CHECK_EXIT_CRITICAL = 2
CHECK_EXIT_OK = 0
CHECK_EXIT_UNKNOWN = 3
CHECK_EXIT_WARNING = 1
_CHECK_KINDS = ("ca", "client", "crl", "server")
_CHECK_SUFFIXES = frozenset({".cer", ".crl", ".crt", ".p12", ".pem", ".pfx"})


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
) -> int:
    """Dispatch a PKI verb and return its exit status.

    Raises ValueError/KeyError/FileNotFoundError on user errors.
    """
    if command == "renew-crl":
        command = "crl"
    handlers: dict[str, Callable[..., int | None]] = {
        "check": _cmd_check,
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
    return handler(args, store=store, theme=theme) or 0


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
    _publish_crl(store, cert_pem, key_pem, revoked=[])
    print(theme.ok(f"CA created: {get_certificate_subject(cert_pem)}"))
    print(theme.dim(f"fingerprint {get_certificate_fingerprint(cert_pem)}"))


def _cmd_check(args: list[str], *, store: CertificateStore | None, theme: Theme) -> int:
    """Check the store, or the given files and directories, for expiry and trust problems.

    Exit status follows the monitoring-plugin convention: 0 all OK, 1 something
    expiring, 2 something expired / not yet valid / revoked / untrusted.
    """
    opts = _parse_flags(
        args, allowed={"by", "ca", "include-revoked", "json", "kind", "password-file", "quiet", "within"}
    )
    flags = opts["flags"]
    within = _parse_within(flags["within"]) if "within" in flags else None
    by = _parse_by(flags["by"]) if "by" in flags else None
    kinds = set(opts["multi"].get("kind", [])) or set(_CHECK_KINDS)
    unknown_kinds = kinds - set(_CHECK_KINDS)
    if unknown_kinds:
        raise ValueError(f"Expected --kind in {', '.join(_CHECK_KINDS)}, got {', '.join(sorted(unknown_kinds))}")

    if opts["positional"]:
        if "include-revoked" in flags:
            raise ValueError("--include-revoked applies to the store only, not to file targets")
        ca_cert_pem = _read_ca_file(Path(flags["ca"])) if "ca" in flags else None
        password = _read_password_file(Path(flags["password-file"])) if "password-file" in flags else None
        rows = _check_targets(
            [Path(target) for target in opts["positional"]],
            within=within,
            by=by,
            ca_cert_pem=ca_cert_pem,
            password=password,
            theme=theme,
        )
        if "kind" in opts["multi"]:
            rows = [row for row in rows if row[1].kind in kinds]
    else:
        if {"ca", "password-file"} & flags.keys():
            raise ValueError("--ca / --password-file apply to file targets; the store uses its own CA")
        store = _require_store(store)
        rows = _check_store(store, within=within, by=by, kinds=kinds, include_revoked="include-revoked" in flags)
    rows.sort(key=lambda row: (row[1].not_after is None, row[1].not_after or datetime.max.replace(tzinfo=UTC)))
    worst = worst_status([result for _, result in rows])
    if "json" in opts["flags"]:
        payload = {"status": worst.value, "results": [_check_row_json(name, result) for name, result in rows]}
        print(json.dumps(payload, indent=2))
    else:
        shown = [row for row in rows if row[1].status is not Status.OK] if "quiet" in opts["flags"] else rows
        _print_check_table(shown, theme)
        if shown or "quiet" not in opts["flags"]:
            print(_check_summary(rows, within=within, by=by))
    if worst is Status.OK:
        return CHECK_EXIT_OK
    return CHECK_EXIT_WARNING if worst is Status.EXPIRING else CHECK_EXIT_CRITICAL


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
    _publish_crl(store, ca_cert, ca_key)
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
    ca_cert, crl = _store_trust_anchors(store, theme)
    _print_cert_summary(
        store.read_certificate_pem(entry), theme, ca_cert_pem=ca_cert, crl_pem=crl, index_revoked_at=entry.revoked_at
    )


def _cmd_revoke(args: list[str], *, store: CertificateStore | None, theme: Theme) -> None:
    store = _require_store(store)
    if not args:
        raise ValueError("Expected revoke <identity|serial>")
    target = store.get_certificate(args[0])
    if target is None:
        raise KeyError(f"Expected issued certificate matching {args[0]!r}")
    entry = store.mark_revoked(args[0])
    ca_cert, ca_key = store.read_ca()
    _publish_crl(store, ca_cert, ca_key)
    print(theme.warn(f"revoked {entry.common_name}"))
    print(theme.dim(f"crl updated: {store.crl_path}"))


def _cmd_delete(args: list[str], *, store: CertificateStore | None, theme: Theme) -> None:
    store = _require_store(store)
    opts = _parse_flags(args, allowed={"force"})
    if not opts["positional"]:
        raise ValueError("Expected delete <identity|serial> [--force]")
    force = "--force" in args or "force" in opts["flags"]
    before = store.get_certificate(opts["positional"][0])
    entry = store.delete_certificate(opts["positional"][0], force=force)
    # Keep crl.pem aligned with tombstones / remaining revoked serials.
    if store.has_ca():
        ca_cert, ca_key = store.read_ca()
        _publish_crl(store, ca_cert, ca_key)
    if before is not None and before.revoked_at is None:
        print(theme.ok(f"revoked and deleted {entry.common_name} (serial {entry.serial_number})"))
    else:
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
        out = Path(opts["flags"].get("out", f"{_safe_export_name(entry.common_name)}.pem"))
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


def _read_ca_file(path: Path) -> bytes:
    data = path.read_bytes()
    try:
        cert = x509.load_pem_x509_certificate(data)
    except ValueError as exc:
        raise ValueError(f"Expected a PEM CA certificate for --ca, got {path}") from exc
    try:
        is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        is_ca = False
    if not is_ca:
        raise ValueError(f"Expected a CA certificate (BasicConstraints ca=True) for --ca, got {path}")
    return data


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
    _publish_crl(store, ca_cert, ca_key)
    print(theme.ok(f"crl regenerated: {store.crl_path}"))


def _print_cert_summary(
    cert_pem: bytes,
    theme: Theme,
    *,
    ca_cert_pem: bytes | None = None,
    crl_pem: bytes | None = None,
    index_revoked_at: str | None = None,
) -> None:
    result = check_certificate(cert_pem, ca_cert_pem=ca_cert_pem, crl_pem=crl_pem)
    if index_revoked_at is not None and result.status is not Status.REVOKED:
        result = _escalate(result, Status.REVOKED, f"revoked in index.json on {index_revoked_at}")
    expiry = get_certificate_expiry(cert_pem)
    status = _styled_status(result, theme)
    print(f"subject   {get_certificate_subject(cert_pem)}")
    print(f"issuer    {get_certificate_issuer(cert_pem)}")
    print(f"serial    {format(get_certificate_serial_number(cert_pem), 'x')}")
    print(f"expires   {expiry.isoformat()} ({status})")
    for reason in result.reasons:
        print(theme.dim(f"          {reason}"))
    print(f"fingerprint {get_certificate_fingerprint(cert_pem)}")
    sans = get_certificate_sans(cert_pem)
    if sans:
        print(f"sans      {', '.join(sans)}")


def _check_file(
    path: Path,
    *,
    within: timedelta | None,
    by: datetime | None,
    ca_cert_pem: bytes | None,
    password: str | None,
) -> list[tuple[str, CertificateStatus]]:
    data = path.read_bytes()
    if path.suffix.lower() in {".p12", ".pfx"}:
        if password is None:
            raise ValueError(f"Expected --password-file to open the PKCS#12 bundle {path}")
        certs = _pkcs12_certificates(data, password, path)
        crls: list[bytes] = []
    else:
        certs, crls = _pem_or_der_artifacts(data, path)
    rows: list[tuple[str, CertificateStatus]] = []
    count = len(certs) + len(crls)
    for index, cert_pem in enumerate(certs, start=1):
        name = str(path) if count == 1 else f"{path} #{index}"
        rows.append((name, check_certificate(cert_pem, within=within, by=by, ca_cert_pem=ca_cert_pem)))
    for index, crl_pem in enumerate(crls, start=len(certs) + 1):
        name = str(path) if count == 1 else f"{path} #{index}"
        rows.append((name, check_crl(crl_pem, within=within, by=by, ca_cert_pem=ca_cert_pem)))
    return rows


def _check_row_json(name: str, result: CertificateStatus) -> dict[str, object]:
    serial = result.serial_number
    return {
        "name": name,
        "kind": result.kind,
        "status": result.status.value,
        "subject": result.subject,
        "issuer": result.issuer,
        "serial_number": None if serial is None else format(serial, "x"),
        "not_before": result.not_before.isoformat(),
        "not_after": None if result.not_after is None else result.not_after.isoformat(),
        "cutoff": result.cutoff.isoformat(),
        "days_remaining": result.days_remaining,
        "reasons": list(result.reasons),
    }


def _check_store(
    store: CertificateStore,
    *,
    within: timedelta | None,
    by: datetime | None,
    kinds: set[str],
    include_revoked: bool,
) -> list[tuple[str, CertificateStatus]]:
    """Check the CA, the CRL, and every issued leaf (revoked ones only on request)."""
    crl_pem = store.read_crl()
    if not store.ca_cert_path.is_file():
        raise FileNotFoundError(f"Expected a CA certificate at {store.ca_cert_path}")
    ca_cert = store.ca_cert_path.read_bytes()
    rows: list[tuple[str, CertificateStatus]] = []
    if "ca" in kinds:
        rows.append(("ca", check_certificate(ca_cert, within=within, by=by, ca_cert_pem=ca_cert)))
    index_revoked = {int(e.serial_number, 16) for e in store.list_certificates(status="revoked")}
    trusted_crl: bytes | None = None
    if crl_pem is None:
        if index_revoked:
            raise FileNotFoundError(
                f"Expected a CRL at {store.crl_path} listing {len(index_revoked)} serial(s) revoked in index.json"
            )
    else:
        crl_result = check_crl(crl_pem, within=within, by=by, ca_cert_pem=ca_cert)
        if crl_result.status is not Status.UNTRUSTED:
            trusted_crl = crl_pem
            listed = {r.serial_number for r in x509.load_pem_x509_crl(crl_pem)}
            missing = sorted(index_revoked - listed)
            if missing:
                shown = ", ".join(format(s, "x") for s in missing[:5]) + (" ..." if len(missing) > 5 else "")
                crl_result = _escalate(
                    crl_result,
                    Status.UNTRUSTED,
                    f"missing {len(missing)} serial(s) revoked in index.json ({shown}); republish with `crl`",
                )
        # An incomplete CRL is reported even when --kind leaves out "crl", like a missing one.
        if "crl" in kinds or crl_result.status is Status.UNTRUSTED:
            rows.append(("crl", crl_result))
    for entry in store.list_certificates(status="all" if include_revoked else "active"):
        if entry.kind not in kinds:
            continue
        cert_pem = store.read_certificate_pem(entry)
        result = check_certificate(cert_pem, within=within, by=by, ca_cert_pem=ca_cert, crl_pem=trusted_crl)
        if entry.revoked_at is not None and result.status is not Status.REVOKED:
            result = _escalate(result, Status.REVOKED, f"revoked in index.json on {entry.revoked_at}")
        rows.append((entry.common_name, result))
    return rows


def _escalate(result: CertificateStatus, status: Status, reason: str) -> CertificateStatus:
    """Add ``reason`` to ``result``, raising its status to ``status`` if that is worse."""
    worst = max(result.status, status, key=lambda s: s.severity)
    return replace(result, status=worst, reasons=(*result.reasons, reason))


def _check_summary(rows: list[tuple[str, CertificateStatus]], *, within: timedelta | None, by: datetime | None) -> str:
    counts = Counter(result.status for _, result in rows)
    parts = [f"{counts[status]} {status.value.replace('_', ' ')}" for status in reversed(Status) if counts[status]]
    if within is not None and by is not None:
        window = f"within {_days(within.days)} or by {by.date().isoformat()}, whichever is earlier"
    elif within is not None:
        window = f"within {_days(within.days)}"
    elif by is not None:
        window = f"by {by.date().isoformat()}"
    else:
        window = "default window (a third of each lifetime, capped)"
    return f"check: {', '.join(parts) or 'nothing to check'}; {window}"


def _check_targets(
    targets: list[Path],
    *,
    within: timedelta | None,
    by: datetime | None,
    ca_cert_pem: bytes | None,
    password: str | None,
    theme: Theme,
) -> list[tuple[str, CertificateStatus]]:
    """Check certificate, chain, CRL, and PKCS#12 files; directories are scanned one level deep."""
    rows: list[tuple[str, CertificateStatus]] = []
    for target in targets:
        if target.is_dir():
            for path in sorted(p for p in target.iterdir() if p.is_file() and p.suffix.lower() in _CHECK_SUFFIXES):
                try:
                    rows.extend(_check_file(path, within=within, by=by, ca_cert_pem=ca_cert_pem, password=password))
                except ValueError as exc:
                    print(theme.dim(f"skipped {path}: {exc}"), file=sys.stderr)
        elif target.exists():
            rows.extend(_check_file(target, within=within, by=by, ca_cert_pem=ca_cert_pem, password=password))
        else:
            raise FileNotFoundError(f"Expected a file or directory to check, got {target}")
    return rows


def _days(count: int) -> str:
    return f"{count} day" if count == 1 else f"{count} days"


def _store_trust_anchors(store: CertificateStore, theme: Theme) -> tuple[bytes | None, bytes | None]:
    """Return the store's CA certificate and CRL, dropping either when unusable.

    Only the CA certificate is read, so stores that keep the CA key offline still work.
    """
    crl = store.read_crl()
    if not store.ca_cert_path.is_file():
        return None, None
    ca_cert = store.ca_cert_path.read_bytes()
    try:
        check_certificate(ca_cert, ca_cert_pem=ca_cert)
    except ValueError as exc:
        print(theme.warn(f"ignoring the store CA and CRL: {exc}"), file=sys.stderr)
        return None, None
    if crl is None:
        return ca_cert, None
    try:
        untrusted = check_crl(crl, ca_cert_pem=ca_cert).status is Status.UNTRUSTED
    except ValueError as exc:
        print(theme.warn(f"ignoring the store CRL: {exc}"), file=sys.stderr)
        return ca_cert, None
    if untrusted:
        print(theme.warn("ignoring the store CRL: it is not signed by the store CA"), file=sys.stderr)
        return ca_cert, None
    return ca_cert, crl


def _style_for(status: Status, theme: Theme) -> Callable[[str], str]:
    if status is Status.OK:
        return theme.ok
    return theme.warn if status is Status.EXPIRING else theme.error


def _styled_status(result: CertificateStatus, theme: Theme) -> str:
    """Render a status for humans, e.g. ``expiring in 12 days`` or ``expired 3 days ago``."""
    days = result.days_remaining
    match result.status:
        case Status.OK:
            return theme.ok("valid" if days is None else f"valid, {_days(days)} left")
        case Status.EXPIRING:
            return theme.warn(f"expiring in {_days(days or 0)}")
        case Status.EXPIRED:
            return theme.error(f"expired {_days(-(days or 0))} ago")
        case _:
            return theme.error(result.status.value.replace("_", " "))


def _parse_by(raw: str) -> datetime:
    """``YYYY-MM-DD`` → the end of that day in local time (timezone-aware)."""
    try:
        day = date.fromisoformat(raw)
    except ValueError as exc:
        raise ValueError(f"Expected --by YYYY-MM-DD, got {raw!r}") from exc
    return datetime.combine(day, time.max).astimezone()


def _parse_within(raw: str) -> timedelta:
    try:
        days = int(raw)
    except ValueError as exc:
        raise ValueError(f"Expected --within as a whole number of days, got {raw!r}") from exc
    if days < 0 or days > MAX_VALIDITY_DAYS:
        raise ValueError(f"Expected --within between 0 and {MAX_VALIDITY_DAYS} days, got {days}")
    return timedelta(days=days)


def _pem_or_der_artifacts(data: bytes, path: Path) -> tuple[list[bytes], list[bytes]]:
    """Split a file into certificate PEMs and CRL PEMs (DER is accepted for a single object)."""
    pem = serialization.Encoding.PEM
    if b"-----BEGIN" not in data:
        try:
            return [x509.load_der_x509_certificate(data).public_bytes(pem)], []
        except ValueError:
            pass
        try:
            return [], [x509.load_der_x509_crl(data).public_bytes(pem)]
        except ValueError as exc:
            raise ValueError(f"Expected a PEM or DER certificate or CRL in {path}") from exc
    certs: list[bytes] = []
    if b"-----BEGIN CERTIFICATE-----" in data:
        certs = [cert.public_bytes(pem) for cert in x509.load_pem_x509_certificates(data)]
    crls: list[bytes] = []
    for block in data.split(b"-----BEGIN X509 CRL-----")[1:]:
        crls.append(x509.load_pem_x509_crl(b"-----BEGIN X509 CRL-----" + block).public_bytes(pem))
    if not certs and not crls:
        raise ValueError(f"Expected a certificate or CRL in {path}, found neither")
    return certs, crls


def _pkcs12_certificates(data: bytes, password: str, path: Path) -> list[bytes]:
    try:
        _, cert, additional = pkcs12.load_key_and_certificates(data, password.encode())
    except ValueError as exc:
        raise ValueError(f"Expected a PKCS#12 bundle that opens with --password-file, got {path}") from exc
    certs = ([cert] if cert is not None else []) + list(additional)
    if not certs:
        raise ValueError(f"Expected a certificate in the PKCS#12 bundle {path}, found none")
    return [c.public_bytes(serialization.Encoding.PEM) for c in certs]


def _print_check_table(rows: list[tuple[str, CertificateStatus]], theme: Theme) -> None:
    if not rows:
        return
    name_width = max(len("name"), *(len(name) for name, _ in rows))
    print(theme.dim(f"{'status':<14}{'kind':<8}{'name':<{name_width + 2}}{'expires':<18}remaining"))
    for name, result in rows:
        expires = "-" if result.not_after is None else result.not_after.astimezone().strftime("%Y-%m-%d %H:%M")
        remaining = "-" if result.days_remaining is None else _days(result.days_remaining)
        label = result.status.value.replace("_", " ")
        styled = _style_for(result.status, theme)(f"{label:<14}")
        print(f"{styled}{result.kind:<8}{name:<{name_width + 2}}{expires:<18}{remaining}")


def _parse_days(raw: str, *, default: int) -> int:
    """Parse ``--days`` into a positive int that cannot overflow datetime math."""
    text = raw.strip() if raw else str(default)
    if not text:
        raise ValueError("Expected a positive integer for --days")
    try:
        days = int(text)
    except ValueError as exc:
        raise ValueError(f"Expected a positive integer for --days, got {raw!r}") from exc
    if days < 1 or days > MAX_VALIDITY_DAYS:
        raise ValueError(f"Expected --days between 1 and {MAX_VALIDITY_DAYS}, got {days}")
    return days


def _parse_flags(args: list[str], *, allowed: set[str]) -> _ParsedFlags:
    """Parse ``--flag value`` / ``--flag`` and collect positionals.

    Repeated ``--san`` / ``--permit`` accumulate in ``multi``. Value-less flags (``--force``)
    never consume the following positional token.
    """
    positional: list[str] = []
    flags: dict[str, str] = {}
    multi: dict[str, list[str]] = {}
    valueless = frozenset(
        {"allow-long-validity", "force", "include-revoked", "json", "legacy", "no-cn-san", "quiet", "yes"}
    )
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
            if not value and name in {"by", "ca", "kind", "out", "password-file", "permit", "san", "within"}:
                raise ValueError(f"Expected a non-empty value for --{name}")
            if name in {"kind", "permit", "san"}:
                multi.setdefault(name, []).append(value)
            else:
                flags[name] = value
            continue
        positional.append(token)
        i += 1
    return {"positional": positional, "flags": flags, "multi": multi}


def _safe_export_name(common_name: str) -> str:
    """Escape path separators for a default export filename.

    ``normalize_subject_attribute`` already rejects ``/`` and ``\\`` for
    newly issued certificates, but a hand-edited or legacy ``index.json``
    entry could still carry one — this keeps ``export pem``'s default
    output path a single component either way.
    """
    return common_name.replace("/", "_").replace("\\", "_")


def _publish_crl(
    store: CertificateStore,
    ca_cert: bytes,
    ca_key: bytes,
    *,
    revoked: list[tuple[int, datetime]] | None = None,
) -> None:
    """Regenerate ``ca/crl.pem`` (default: the index's revoked set) with a CRL number above every earlier one."""
    entries = store.revoked_entries() if revoked is None else revoked
    crl = generate_crl(ca_cert, ca_key, entries, crl_number=store.next_crl_number())
    store.write_crl(crl)


def _write_secret_file(path: Path, data: str | bytes) -> None:
    """Write an export with mode 0600, refusing to write through a symlink at ``path``."""
    payload = data.encode() if isinstance(data, str) else data
    write_file_atomic(path, payload, mode=0o600)
