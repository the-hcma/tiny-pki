"""PKI command handlers for the tiny-pki REPL.

Shell chrome lives in ``main``; this module implements init/create/show/…
"""

from __future__ import annotations

import getpass
import json
import os
import stat
import sys
import warnings
from collections import Counter
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, date, datetime, time, timedelta
from pathlib import Path
from typing import TypedDict, cast

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from tiny_pki import (
    DEFAULT_CA_VALIDITY_DAYS,
    DEFAULT_CLIENT_VALIDITY_DAYS,
    DEFAULT_INTERMEDIATE_VALIDITY_DAYS,
    DEFAULT_KEY_TYPE,
    DEFAULT_ORGANIZATION_NAME,
    DEFAULT_SERVER_VALIDITY_DAYS,
    KEY_TYPES,
    MAX_OCSP_VALIDITY_DAYS,
    MAX_STORE_CRL_VALIDITY_DAYS,
    MAX_VALIDITY_DAYS,
    CsrSummary,
    KeyType,
    TinyPkiWarning,
    generate_ca_certificate,
    generate_pkcs12,
    get_certificate_expiry,
    get_certificate_fingerprint,
    get_certificate_issuer,
    get_certificate_sans,
    get_certificate_serial_number,
    get_certificate_subject,
    get_certificate_uris,
    inspect_csr,
)
from tiny_pki._csr import is_csr_data, load_csr, requested_sans
from tiny_pki._fsutil import write_file_atomic, write_files_atomic
from tiny_pki.check import CertificateStatus, Status, check_certificate, check_crl, worst_status
from tiny_pki.cli.commands import COMMAND_FLAGS
from tiny_pki.cli.theme import Theme
from tiny_pki.constants import URI_SUBTREE_PREFIX
from tiny_pki.names import common_name_as_san, normalize_san_entries, normalize_san_entry
from tiny_pki.store import CHECK_KINDS, CertificateStore, CheckKind, IssuedCertificate, check_store

CHECK_EXIT_CRITICAL = 2
CHECK_EXIT_OK = 0
CHECK_EXIT_UNKNOWN = 3
CHECK_EXIT_WARNING = 1
_CHECK_KINDS = tuple(sorted(CHECK_KINDS))
_CHECK_SUFFIXES = frozenset({".cer", ".crl", ".crt", ".p12", ".pem", ".pfx"})
_KEY_HOLDER = {"client": "device", "intermediate": "intermediate CA", "server": "server"}
_SIGN_DEFAULT_DAYS = {
    "client": DEFAULT_CLIENT_VALIDITY_DAYS,
    "intermediate": DEFAULT_INTERMEDIATE_VALIDITY_DAYS,
    "server": DEFAULT_SERVER_VALIDITY_DAYS,
}


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
        "decrypt-key": _cmd_decrypt_key,
        "delete": _cmd_delete,
        "encrypt-key": _cmd_encrypt_key,
        "export": _cmd_export,
        "init": _cmd_init,
        "inspect": _cmd_inspect,
        "list": _cmd_list,
        "ocsp": _cmd_ocsp,
        "revoke": _cmd_revoke,
        "show": _cmd_show,
        "sign": _cmd_sign,
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


def _confirm_csr_sans(
    csr: x509.CertificateSigningRequest, name: str, sans: list[str], *, include_cn: bool, flags: dict[str, str]
) -> bool:
    """Decide whether the SANs a server CSR requests, beyond ``--san`` and the CN, are included.

    ``--accept-csr-sans`` includes them; otherwise the operator is asked, and a
    non-interactive stdin declines (the library then warns that they were ignored).
    """
    covered = set(normalize_san_entries(sans))
    cn_san = common_name_as_san(name)
    if cn_san is not None and include_cn:
        covered.add(cn_san)
    extra = [san for san in requested_sans(csr) if _normalized_san(san) not in covered]
    if not extra:
        return False
    if "accept-csr-sans" in flags:
        return True
    if not sys.stdin.isatty():
        return False
    try:
        answer = input(f"The CSR also requests SANs {', '.join(extra)}. Include them? [y/N] ")
    except (EOFError, KeyboardInterrupt) as exc:
        raise ValueError(
            "Expected an answer to the CSR SAN prompt; pass --accept-csr-sans or list them with --san"
        ) from exc
    return answer.strip().lower() in {"y", "yes"}


def _normalized_san(san: str) -> str:
    try:
        return normalize_san_entry(san)
    except ValueError:
        return san


def _require_store(store: CertificateStore | None) -> CertificateStore:
    if store is None:
        raise ValueError("Expected --store / TINY_PKI_STORE for this command")
    return store


def _cmd_init(args: list[str], *, store: CertificateStore | None, theme: Theme) -> None:
    store = _require_store(store)
    opts = _parse_flags(args, command="init")
    if opts["positional"]:
        raise ValueError("init takes no positional arguments; use --cn / --org")
    if store.has_ca():
        raise ValueError(f"CA already exists under {store.root}")
    flags = opts["flags"]
    if "issuer-key-secret-file" in flags and "intermediate-of" not in flags:
        raise ValueError("--issuer-key-secret-file requires --intermediate-of")
    if "path-length" in flags and "intermediate-of" in flags:
        raise ValueError("--path-length applies to a root CA; an intermediate CA always signs leaves only")
    path_length = _parse_path_length(flags["path-length"]) if "path-length" in flags else 0
    issuer = CertificateStore(flags["intermediate-of"]) if "intermediate-of" in flags else None
    if issuer is not None and not issuer.has_ca():
        raise ValueError(f"Expected a CA under --intermediate-of {issuer.root}")
    encrypted_key = "encrypt-key" in flags
    if "key-secret-file" in flags and not encrypted_key:
        raise ValueError("--key-secret-file requires --encrypt-key for init")
    issuer_key_secret = _issuer_key_secret(flags, issuer=issuer, theme=theme) if issuer is not None else None
    key_secret = _required_key_secret(flags, store=store, theme=theme, confirm=True) if encrypted_key else None
    crl_days = _parse_crl_days(flags["crl-days"], "--crl-days") if "crl-days" in flags else None
    if issuer is not None:
        _init_intermediate(
            store,
            issuer,
            opts,
            key_secret=key_secret,
            issuer_key_secret=issuer_key_secret,
            crl_days=crl_days,
            theme=theme,
        )
        if encrypted_key and "key-secret-file" in flags:
            _offer_to_remove_key_secret_file(Path(flags["key-secret-file"]), theme)
        return
    cn = opts["flags"].get("cn", "Private CA")
    org = opts["flags"].get("org", DEFAULT_ORGANIZATION_NAME)
    days = _parse_days(opts["flags"].get("days", str(DEFAULT_CA_VALIDITY_DAYS)), default=DEFAULT_CA_VALIDITY_DAYS)
    key_type, key_size = _parse_key_options(opts["flags"])
    cert_pem, key_pem = generate_ca_certificate(
        cn,
        organization_name=org,
        validity_days=days,
        key_size=key_size,
        key_type=key_type,
        permitted_subtrees=_permitted_subtrees(opts),
        path_length=path_length,
    )
    store.write_ca(cert_pem, key_pem, key_secret=key_secret)
    store.publish_crl(validity_days=crl_days, key_secret=key_secret)
    print(theme.ok(f"CA created: {get_certificate_subject(cert_pem)}"))
    print(theme.dim(f"fingerprint {get_certificate_fingerprint(cert_pem)}"))
    if path_length:
        print(theme.dim("it may sign intermediate CAs: init --intermediate-of or sign intermediate"))
    if encrypted_key and "key-secret-file" in opts["flags"]:
        _offer_to_remove_key_secret_file(Path(opts["flags"]["key-secret-file"]), theme)


def _permitted_subtrees(opts: _ParsedFlags) -> list[str] | None:
    subtrees = [
        *opts["multi"].get("permit", []),
        *(URI_SUBTREE_PREFIX + h for h in opts["multi"].get("permit-uri", [])),
    ]
    return subtrees or None


def _init_intermediate(
    store: CertificateStore,
    issuer: CertificateStore,
    opts: _ParsedFlags,
    *,
    key_secret: str | None,
    issuer_key_secret: str | None,
    crl_days: int | None,
    theme: Theme,
) -> None:
    flags = opts["flags"]
    days = _parse_days(
        flags.get("days", str(DEFAULT_INTERMEDIATE_VALIDITY_DAYS)), default=DEFAULT_INTERMEDIATE_VALIDITY_DAYS
    )
    key_type, key_size = _parse_key_options(flags)
    entry = store.init_intermediate(
        issuer,
        flags.get("cn") or "Intermediate CA",
        organization_name=flags.get("org") or None,
        validity_days=days,
        key_size=key_size,
        key_type=key_type,
        permitted_subtrees=_permitted_subtrees(opts),
        key_secret=key_secret,
        issuer_key_secret=issuer_key_secret,
        crl_validity_days=crl_days,
    )
    cert_pem = store.read_ca_certificate()
    print(theme.ok(f"intermediate CA created: {get_certificate_subject(cert_pem)}, signed by {issuer.root}"))
    print(theme.dim(f"fingerprint {get_certificate_fingerprint(cert_pem)}"))
    print(theme.dim(f"recorded in the issuer's index as serial {entry.serial_number}; its key never left {store.root}"))
    print(
        theme.dim(
            f"TLS servers trust {store.public_dir / 'ca-chain.pem'} and check {store.public_dir / 'crl.pem'}; "
            "import each new issuer CRL with crl --chain-crl PATH"
        )
    )


def _cmd_check(args: list[str], *, store: CertificateStore | None, theme: Theme) -> int:
    """Check the store, or the given files and directories, for expiry and trust problems.

    Exit status follows the monitoring-plugin convention: 0 all OK, 1 something
    expiring, 2 something expired / not yet valid / revoked / untrusted.
    """
    opts = _parse_flags(args, command="check")
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
        crl_pem = _read_crl_file(Path(flags["crl"]), ca_cert_pem) if "crl" in flags else None
        password = _read_password_file(Path(flags["password-file"])) if "password-file" in flags else None
        rows = _check_targets(
            [Path(target) for target in opts["positional"]],
            within=within,
            by=by,
            ca_cert_pem=ca_cert_pem,
            crl_pem=crl_pem,
            password=password,
            theme=theme,
        )
        if "kind" in opts["multi"]:
            rows = [row for row in rows if row[1].kind in kinds]
    else:
        if {"ca", "crl", "password-file"} & flags.keys():
            raise ValueError("--ca / --crl / --password-file apply to file targets; the store uses its own CA and CRL")
        store = _require_store(store)
        rows = check_store(
            store,
            within=within,
            by=by,
            kinds=cast(set[CheckKind], kinds),
            include_revoked="include-revoked" in flags,
        )
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
    opts = _parse_flags(args[1:], command="create")
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
    if kind == "server" and {"keep-previous", "uri-san"} & opts["flags"].keys():
        raise ValueError("--keep-previous / --uri-san are only supported for client certificates")
    if "no-cn-san" in opts["flags"] and not opts["multi"].get("san"):
        raise ValueError("Expected --san with --no-cn-san; without --san the CN is the only SAN")
    key_secret = _key_secret(opts["flags"], store=store, theme=theme)
    default_days = DEFAULT_CLIENT_VALIDITY_DAYS if kind == "client" else DEFAULT_SERVER_VALIDITY_DAYS
    days = _parse_days(opts["flags"].get("days", str(default_days)), default=default_days)
    key_type, key_size = _parse_key_options(opts["flags"])
    org = opts["flags"].get("org")
    allow_long_validity = "allow-long-validity" in opts["flags"]
    allow_dn_special_chars = "allow-dn-special-chars" in opts["flags"]

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", TinyPkiWarning)
        if kind == "client":
            entry = store.issue_client(
                name,
                organization_name=org,
                validity_days=days,
                key_size=key_size,
                key_type=key_type,
                allow_long_validity=allow_long_validity,
                allow_dn_special_chars=allow_dn_special_chars,
                keep_previous="keep-previous" in opts["flags"],
                key_secret=key_secret,
                uri_san=opts["flags"].get("uri-san"),
            )
        else:
            sans = [s for s in opts["multi"].get("san", []) if s] or [name]
            entry = store.issue_server(
                name,
                sans,
                organization_name=org,
                validity_days=days,
                key_size=key_size,
                key_type=key_type,
                allow_long_validity=allow_long_validity,
                include_common_name_in_sans=_confirm_cn_in_sans(name, sans, opts["flags"]),
                allow_dn_special_chars=allow_dn_special_chars,
                key_secret=key_secret,
            )
    for warning in caught:
        print(theme.warn(f"warning: {warning.message}"), file=sys.stderr)

    print(theme.ok(f"issued {kind} {entry.common_name}"))
    print(theme.dim(f"serial {entry.serial_number}  fp {entry.fingerprint}"))
    if "keep-previous" in opts["flags"]:
        _print_superseded_hints(store, entry, theme)


def _cmd_sign(args: list[str], *, store: CertificateStore | None, theme: Theme) -> None:
    store = _require_store(store)
    if not args:
        raise ValueError("Expected sign client|server|intermediate <name> --csr PATH")
    kind = args[0]
    if kind not in _SIGN_DEFAULT_DAYS:
        raise ValueError(f"Expected sign client|server|intermediate, got {kind!r}")
    opts = _parse_flags(args[1:], command="sign")
    flags = opts["flags"]
    name = _require_one_positional(opts, f"sign {kind} <name> --csr PATH")
    server_only = {"accept-csr-sans", "no-cn-san", "yes"} & flags.keys()
    leaf_only = {"allow-dn-special-chars", "allow-long-validity", "keep-previous"} & flags.keys()
    if kind == "intermediate" and (opts["multi"].get("san") or server_only or leaf_only):
        raise ValueError(
            "--san / --accept-csr-sans / --no-cn-san / --yes / --keep-previous / --allow-long-validity / "
            "--allow-dn-special-chars do not apply to intermediate CAs"
        )
    if kind != "intermediate" and (opts["multi"].get("permit") or opts["multi"].get("permit-uri")):
        raise ValueError("--permit / --permit-uri are only supported for intermediate CAs")
    if kind != "client" and "uri-san" in flags:
        raise ValueError("--uri-san is only supported for client certificates")
    if kind == "client" and (opts["multi"].get("san") or server_only):
        raise ValueError("--san / --accept-csr-sans / --no-cn-san / --yes are only supported for server certificates")
    if kind == "server" and "keep-previous" in flags:
        raise ValueError("--keep-previous is only supported for client certificates")
    if "no-cn-san" in flags and not opts["multi"].get("san"):
        raise ValueError("Expected --san with --no-cn-san; without --san the CN is the only SAN")
    csr_flag = flags.get("csr")
    if not csr_flag:
        raise ValueError("Expected --csr PATH with the certificate signing request")
    csr_path = Path(csr_flag)
    try:
        csr_pem = csr_path.read_bytes()
    except OSError as exc:
        raise ValueError(f"Expected a readable --csr file, got {csr_path} ({exc.strerror})") from exc
    default_days = _SIGN_DEFAULT_DAYS[kind]
    days = _parse_days(flags.get("days", str(default_days)), default=default_days)
    org = flags.get("org")
    allow_long_validity = "allow-long-validity" in flags
    allow_dn_special_chars = "allow-dn-special-chars" in flags
    sans: list[str] = []
    include_cn = include_csr_sans = False
    if kind == "server":
        sans = [s for s in opts["multi"].get("san", []) if s] or [name]
        include_cn = _confirm_cn_in_sans(name, sans, flags)
        include_csr_sans = _confirm_csr_sans(load_csr(csr_pem), name, sans, include_cn=include_cn, flags=flags)
    key_secret = _key_secret(flags, store=store, theme=theme)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", TinyPkiWarning)
        if kind == "client":
            entry = store.sign_client_csr(
                name,
                csr_pem,
                organization_name=org,
                validity_days=days,
                allow_long_validity=allow_long_validity,
                allow_dn_special_chars=allow_dn_special_chars,
                keep_previous="keep-previous" in flags,
                key_secret=key_secret,
                uri_san=flags.get("uri-san"),
            )
        elif kind == "intermediate":
            entry = store.sign_intermediate_csr(
                name,
                csr_pem,
                organization_name=org,
                validity_days=days,
                permitted_subtrees=_permitted_subtrees(opts),
                key_secret=key_secret,
            )
        else:
            entry = store.sign_server_csr(
                name,
                csr_pem,
                sans,
                organization_name=org,
                validity_days=days,
                allow_long_validity=allow_long_validity,
                include_common_name_in_sans=include_cn,
                include_csr_sans=include_csr_sans,
                allow_dn_special_chars=allow_dn_special_chars,
                key_secret=key_secret,
            )
    for warning in caught:
        print(theme.warn(f"warning: {warning.message}"), file=sys.stderr)

    holder = _KEY_HOLDER[kind]
    print(theme.ok(f"issued {kind} {entry.common_name} from {csr_path} (the private key stays on the {holder})"))
    print(theme.dim(f"serial {entry.serial_number}  fp {entry.fingerprint}"))
    out_flag = opts["flags"].get("out")
    if out_flag:
        out = Path(out_flag)
        write_file_atomic(out, store.read_certificate_pem(entry), mode=0o644)
        print(theme.ok(f"wrote {out}"))
    if "keep-previous" in opts["flags"]:
        _print_superseded_hints(store, entry, theme)


def _print_superseded_hints(store: CertificateStore, entry: IssuedCertificate, theme: Theme) -> None:
    for old, new in store.superseded_serials().items():
        if new == entry.serial_number:
            hint = f"previous serial {old} stays live; run `revoke 0x{old}` once the device has the new one"
            print(theme.warn(hint))


def _cmd_show(args: list[str], *, store: CertificateStore | None, theme: Theme) -> None:
    store = _require_store(store)
    target = args[0] if args else "certs"
    if target in {"ca", "certs", "clients", "intermediates", "servers", "revoked"}:
        _cmd_list([target, *args[1:]], store=store, theme=theme)
        return
    _require_one_positional(_parse_flags(args, command="show"), "show ca|certs|crl|<identity>")
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
    opts = _parse_flags(args, command="list")
    as_json = "json" in opts["flags"]
    positional = opts["positional"]
    if len(positional) > 1:
        raise ValueError(f"Unexpected extra arguments: {' '.join(positional[1:])}")
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
    if target == "intermediates":
        _print_entry_list(
            store.list_certificates(kind="intermediate", status="active"),
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
    raise ValueError(f"Expected list ca|clients|servers|intermediates|revoked|certs, got {target!r}")


def _list_ca(store: CertificateStore, *, theme: Theme, as_json: bool) -> None:
    ca_cert = store.read_ca_certificate()
    chain = x509.load_pem_x509_certificates(store.read_ca_chain())[1:]
    if as_json:
        print(
            json.dumps(
                {
                    "chain": [get_certificate_subject(cert.public_bytes(serialization.Encoding.PEM)) for cert in chain],
                    "chain_path": str(store.ca_chain_path) if chain else None,
                    "cn": get_certificate_subject(ca_cert),
                    "fingerprint": get_certificate_fingerprint(ca_cert),
                    "expires": get_certificate_expiry(ca_cert).isoformat(),
                    "cert_path": str(store.ca_cert_path),
                    "crl_path": str(store.crl_path),
                    "crl_days": store.crl_validity_days,
                    "public_dir": str(store.public_dir),
                    "index_path": str(store.index_path),
                    "ocsp_days": store.ocsp_validity_days,
                    "ocsp_dir": str(store.ocsp_dir),
                    "ocsp_url": store.ocsp_url,
                },
                sort_keys=True,
            )
        )
        return
    _print_cert_summary(ca_cert, theme)
    print(theme.dim(f"cert {store.ca_cert_path}"))
    if chain:
        names = " -> ".join(get_certificate_subject(cert.public_bytes(serialization.Encoding.PEM)) for cert in chain)
        print(theme.dim(f"chain {store.ca_chain_path} (intermediate CA; issued by {names})"))
    print(theme.dim(f"crl  {store.crl_path} (valid {store.crl_validity_days} days per publish)"))
    print(theme.dim(f"index {store.index_path}"))
    published = "ca.crt + ca-chain.pem + crl.pem (own and issuer CRLs)" if chain else "ca.crt + crl.pem"
    print(theme.dim(f"public {store.public_dir} ({published} for TLS servers; no key)"))
    ocsp_days = store.ocsp_validity_days
    if ocsp_days is not None:
        print(theme.dim(f"ocsp {store.ocsp_dir} (stapling responses, valid {ocsp_days} days per publish)"))
    if store.ocsp_url is not None:
        print(theme.dim(f"ocsp url {store.ocsp_url} (in new certificates)"))


def _list_summary(store: CertificateStore, *, theme: Theme, as_json: bool) -> None:
    clients = store.list_certificates(kind="client", status="active")
    servers = store.list_certificates(kind="server", status="active")
    intermediates = store.list_certificates(kind="intermediate", status="active")
    revoked = store.list_certificates(status="revoked")
    ca_cn = get_certificate_subject(store.read_ca_certificate()) if store.has_ca() else None
    if as_json:
        print(
            json.dumps(
                {
                    "ca_cn": ca_cn,
                    "clients": len(clients),
                    "intermediates": len(intermediates),
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
    counts = f"clients {len(clients)}  servers {len(servers)}  revoked {len(revoked)}"
    if intermediates:
        counts += f"  intermediates {len(intermediates)}"
    print(theme.dim(counts))
    print(theme.dim(f"store {store.root}"))


def _print_entry_list(
    entries: list[IssuedCertificate],
    *,
    store: CertificateStore,
    theme: Theme,
    as_json: bool,
) -> None:
    superseded = store.superseded_serials()
    if as_json:
        rows = [
            {
                "superseded_by": superseded.get(e.serial_number) if not e.revoked_at else None,
                "cn": e.common_name,
                "kind": e.kind,
                "serial": e.serial_number,
                "fingerprint": e.fingerprint,
                "expires": e.not_valid_after,
                "status": "revoked" if e.revoked_at else "active",
                "uri_san": e.uri_san,
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
        newer = None if entry.revoked_at else superseded.get(entry.serial_number)
        status = "revoked" if entry.revoked_at else "active"
        color = theme.error if entry.revoked_at else theme.ok
        note = f"  superseded by {newer}" if newer else ""
        uri = f"  uri={entry.uri_san}" if entry.uri_san else ""
        print(
            f"{color(status)}  {entry.kind:6}  {entry.common_name}  "
            f"serial={entry.serial_number}  expires={entry.not_valid_after}{uri}{theme.warn(note) if note else ''}"
        )


def _cmd_inspect(args: list[str], *, store: CertificateStore | None, theme: Theme) -> None:
    target = _require_one_positional(_parse_flags(args, command="inspect"), "inspect <identity|path>")
    path = Path(target)
    if path.is_file():
        data = path.read_bytes()
        if is_csr_data(data):
            _print_csr_summary(inspect_csr(data), theme)
        else:
            _print_cert_summary(data, theme)
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
    opts = _parse_flags(args, command="revoke")
    identity = _require_one_positional(opts, "revoke <identity|serial> [--dry-run]")
    target = store.get_certificate(identity, require_unique=True)
    if target is None:
        raise KeyError(f"Expected issued certificate matching {identity!r}")
    if "dry-run" in opts["flags"]:
        if target.revoked_at is None:
            print(theme.warn(f"would revoke {target.kind} {target.common_name} (serial {target.serial_number})"))
            print(theme.dim(f"would update {store.crl_path}"))
        else:
            print(theme.dim(f"{target.common_name} is already revoked (at {target.revoked_at}); nothing to do"))
        print(theme.dim("dry run: nothing written"))
        return
    key_secret = _key_secret(opts["flags"], store=store, theme=theme)
    entry = store.revoke(identity, key_secret=key_secret)
    print(theme.warn(f"revoked {entry.common_name}"))
    if store.has_ca():
        print(theme.dim(f"crl updated: {store.crl_path}"))
    else:
        print(theme.warn(f"warning: no CA under {store.root}, so no CRL was published"), file=sys.stderr)


def _cmd_delete(args: list[str], *, store: CertificateStore | None, theme: Theme) -> None:
    store = _require_store(store)
    opts = _parse_flags(args, command="delete")
    identity = _require_one_positional(opts, "delete <identity|serial> [--force] [--dry-run]")
    force = "force" in opts["flags"]
    before = store.get_certificate(identity, require_unique=True)
    if "dry-run" in opts["flags"]:
        if before is None:
            raise KeyError(f"Expected issued certificate matching {identity!r}")
        if before.revoked_at is None and not force:
            raise ValueError(
                f"Certificate {before.common_name!r} is still active; revoke it first, "
                "or pass --force to revoke and delete it in one step"
            )
        verb = "revoke and delete" if before.revoked_at is None else "delete"
        print(theme.warn(f"would {verb} {before.kind} {before.common_name} (serial {before.serial_number})"))
        print(theme.dim("dry run: nothing written"))
        return
    key_secret = _key_secret(opts["flags"], store=store, theme=theme)
    entry = store.delete(identity, force=force, key_secret=key_secret)
    if before is not None and before.revoked_at is None:
        print(theme.ok(f"revoked and deleted {entry.common_name} (serial {entry.serial_number})"))
    else:
        print(theme.ok(f"deleted {entry.common_name}"))


def _cmd_export(args: list[str], *, store: CertificateStore | None, theme: Theme) -> None:
    store = _require_store(store)
    if len(args) < 2:
        raise ValueError(
            "Expected export pem|p12 <identity> [--out PATH] [--cert-out PATH --key-out PATH] [--ca-out PATH] "
            "[--legacy] [--password-file PATH]"
        )
    fmt = args[0]
    opts = _parse_flags(args[1:], command="export")
    flags = opts["flags"]
    identity = _require_one_positional(opts, f"export {fmt} <identity>")
    entry = store.get_certificate(identity)
    if entry is None:
        raise KeyError(f"Expected issued certificate matching {identity!r}")
    if fmt not in {"pem", "p12"}:
        raise ValueError(f"Expected export pem|p12, got {fmt!r}")
    if fmt == "p12" and {"cert-out", "key-out", "ca-out"} & flags.keys():
        raise ValueError("--cert-out / --key-out / --ca-out are only supported for export pem")
    if fmt == "pem":
        _export_pem(store, entry, flags, theme)
        return
    if not entry.key_path:
        if entry.kind == "intermediate":
            raise ValueError(
                f"Expected a leaf to build a PKCS#12 bundle, but {entry.common_name!r} is an intermediate CA whose "
                "key lives in its own store; use export pem for the certificate"
            )
        raise ValueError(
            f"Expected a private key for {entry.common_name!r} to build a PKCS#12 bundle, but it was signed "
            f"from a CSR and its key stays on the {_KEY_HOLDER[entry.kind]}; use export pem for the certificate"
        )
    cert_pem = store.read_certificate_pem(entry)
    key_pem = store.read_key_pem(entry)
    password_file = flags.get("password-file")
    password = _read_password_file(Path(password_file)) if password_file else _prompt_p12_password()
    p12 = generate_pkcs12(
        cert_pem, key_pem, store.read_ca_chain(), entry.common_name, password.encode(), legacy="legacy" in flags
    )
    out_flag = flags.get("out")
    if out_flag:
        path = Path(out_flag)
        _write_secret_file(path, p12)
    else:
        path = store.write_bundle(entry.common_name, p12, serial_number=entry.serial_number)
    print(theme.ok(f"wrote {path}"))
    if password_file:
        _offer_to_remove_password_file(Path(password_file), theme)


def _export_pem(store: CertificateStore, entry: IssuedCertificate, flags: dict[str, str], theme: Theme) -> None:
    has_key = bool(entry.key_path)
    split = {"cert-out", "key-out"} & flags.keys()
    if split and "out" in flags:
        raise ValueError("Expected either --out or --cert-out / --key-out, not both")
    if "key-out" in flags and not has_key:
        raise ValueError(
            f"Expected a private key for {entry.common_name!r} to write --key-out, but its key stays on the "
            f"{_KEY_HOLDER[entry.kind]}; use --cert-out alone"
        )
    if has_key and len(split) == 1:
        raise ValueError("Expected --cert-out and --key-out together")
    cert_pem = store.read_certificate_pem(entry)
    holder_note = f"certificate only: the private key stays on the {_KEY_HOLDER[entry.kind]}"
    outputs: list[tuple[Path, bytes, int, str]] = []
    if split:
        outputs.append((Path(flags["cert-out"]), cert_pem, 0o644, "certificate" if has_key else holder_note))
        if has_key:
            outputs.append((Path(flags["key-out"]), store.read_key_pem(entry), 0o600, "private key"))
    else:
        out = Path(flags.get("out", f"{_safe_export_name(entry.common_name)}.pem"))
        if has_key:
            outputs.append((out, cert_pem + store.read_key_pem(entry), 0o600, ""))
        else:
            outputs.append((out, cert_pem, 0o644, holder_note))
    if "ca-out" in flags:
        outputs.append((Path(flags["ca-out"]), store.read_ca_chain(), 0o644, "CA certificate"))
    _require_distinct_export_paths([path for path, _, _, _ in outputs])
    write_files_atomic([(path, data, mode) for path, data, mode, _ in outputs])
    for path, _, _, what in outputs:
        print(theme.ok(f"wrote {path} ({what})" if what else f"wrote {path}"))


def _require_distinct_export_paths(paths: list[Path]) -> None:
    seen: dict[Path, Path] = {}
    for path in paths:
        if path.is_dir():
            raise ValueError(f"Expected a file path to export to, got directory {path}")
        if not path.parent.is_dir():
            raise ValueError(f"Expected an existing directory for {path}")
        key = path.parent.resolve() / path.name
        if key in seen or any(path.exists() and other.exists() and path.samefile(other) for other in seen.values()):
            raise ValueError(f"Expected a different path for each export, got {path} twice")
        seen[key] = path


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


def _read_crl_file(path: Path, ca_cert_pem: bytes | None) -> bytes:
    """Load ``--crl`` (PEM or DER) and require it to be signed by ``--ca``."""
    if ca_cert_pem is None:
        raise ValueError("Expected --ca with --crl so the CRL signature can be verified")
    _, crls = _pem_or_der_artifacts(path.read_bytes(), path)
    if len(crls) != 1:
        raise ValueError(f"Expected exactly one CRL in {path} for --crl, found {len(crls)}")
    if check_crl(crls[0], ca_cert_pem=ca_cert_pem).status is Status.UNTRUSTED:
        raise ValueError(f"Expected a --crl signed by the --ca certificate, got {path}")
    return crls[0]


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


def _key_secret(
    flags: dict[str, str],
    *,
    store: CertificateStore,
    theme: Theme,
    required: bool = False,
    confirm: bool = False,
) -> str | None:
    """Load a CA-key secret from a file/credential or prompt without exposing it in argv."""
    explicit_path = flags.get("key-secret-file")
    if not required and not store.ca_key_encrypted:
        if explicit_path is not None:
            raise ValueError("--key-secret-file was given but the CA private key is not encrypted")
        return None
    secret_path = explicit_path or os.environ.get("TINY_PKI_KEY_SECRET_FILE")
    if secret_path is None:
        credentials_dir = os.environ.get("CREDENTIALS_DIRECTORY")
        if credentials_dir is not None:
            credential = Path(credentials_dir) / "tiny-pki-key"
            if credential.is_file():
                secret_path = str(credential)
    if secret_path is not None:
        return _read_key_secret_file(Path(secret_path), theme=theme)
    if not sys.stdin.isatty():
        raise ValueError(
            "Expected --key-secret-file PATH, TINY_PKI_KEY_SECRET_FILE, or systemd tiny-pki-key credential"
        )
    try:
        secret = getpass.getpass("CA key secret: ")
        if not secret:
            raise ValueError("Expected a non-empty CA key secret")
        if confirm and getpass.getpass("Repeat CA key secret: ") != secret:
            raise ValueError("Expected the repeated CA key secret to match")
    except EOFError as exc:
        raise ValueError("Expected a CA key secret") from exc
    return secret


def _required_key_secret(flags: dict[str, str], *, store: CertificateStore, theme: Theme, confirm: bool = False) -> str:
    secret = _key_secret(flags, store=store, theme=theme, required=True, confirm=confirm)
    if secret is None:
        raise ValueError("Expected a CA key secret")
    return secret


def _issuer_key_secret(flags: dict[str, str], *, issuer: CertificateStore, theme: Theme) -> str | None:
    """Load the ``--intermediate-of`` store's CA-key secret; the environment sources are this store's, not its."""
    path = flags.get("issuer-key-secret-file")
    if not issuer.ca_key_encrypted:
        if path is not None:
            raise ValueError("--issuer-key-secret-file was given but the issuer's CA private key is not encrypted")
        return None
    if path is not None:
        return _read_key_secret_file(Path(path), theme=theme)
    if not sys.stdin.isatty():
        raise ValueError("Expected --issuer-key-secret-file PATH for the issuer's encrypted CA private key")
    try:
        secret = getpass.getpass("Issuer CA key secret: ")
    except EOFError as exc:
        raise ValueError("Expected the issuer's CA key secret") from exc
    if not secret:
        raise ValueError("Expected a non-empty issuer CA key secret")
    return secret


def _read_key_secret_file(path: Path, *, theme: Theme) -> str:
    """Read the first UTF-8 line from a secret file without echoing its contents."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Expected a readable CA key secret file, got {path} ({exc.strerror})") from exc
    except UnicodeDecodeError as exc:
        raise ValueError(f"Expected a UTF-8 CA key secret file, got undecodable bytes in {path}") from exc
    lines = text.splitlines()
    secret = lines[0] if lines else ""
    if not secret:
        raise ValueError(f"Expected a non-empty CA key secret on the first line of {path}")
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError as exc:
        print(theme.warn(f"warning: could not verify permissions on CA key secret file {path}: {exc}"), file=sys.stderr)
    else:
        if mode & 0o077:
            print(
                theme.warn(f"warning: CA key secret file {path} is accessible to group or other users"),
                file=sys.stderr,
            )
    return secret


def _offer_to_remove_key_secret_file(path: Path, theme: Theme) -> None:
    """Offer to remove a secret staging file after encrypting the CA key."""
    print(theme.warn(f"warning: {path} contains the CA key secret in plaintext"), file=sys.stderr)
    resolved_path = path.resolve()
    configured_path = os.environ.get("TINY_PKI_KEY_SECRET_FILE")
    if configured_path and resolved_path == Path(configured_path).expanduser().resolve():
        print(theme.warn(f"warning: keeping {path}; TINY_PKI_KEY_SECRET_FILE points to this file"), file=sys.stderr)
        return
    credentials_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if credentials_dir:
        resolved_credentials_dir = Path(credentials_dir).expanduser().resolve()
        if resolved_path.is_relative_to(resolved_credentials_dir):
            print(theme.warn(f"warning: keeping {path}; it is under CREDENTIALS_DIRECTORY"), file=sys.stderr)
            return
    if not sys.stdin.isatty():
        print(
            theme.warn(f"warning: left {path} in place; remove it after provisioning a durable secret source"),
            file=sys.stderr,
        )
        return
    try:
        answer = input(f"Remove temporary secret file {path} now? [y/N] ")
    except (EOFError, KeyboardInterrupt):
        answer = "n"
    if answer.strip().lower() in {"y", "yes"}:
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            print(theme.warn(f"warning: could not remove {path}: {exc}"), file=sys.stderr)
        else:
            print(theme.ok(f"removed {path}"))
    else:
        print(
            theme.warn(f"warning: left {path} in place; protect it and remove it when no longer needed"),
            file=sys.stderr,
        )


def _cmd_crl(args: list[str], *, store: CertificateStore | None, theme: Theme) -> None:
    opts = _parse_flags(args, command="crl")
    if opts["positional"]:
        raise ValueError(f"crl takes no positional arguments, got {' '.join(opts['positional'])}")
    days = _parse_crl_days(opts["flags"]["days"], "--days") if "days" in opts["flags"] else None
    store = _require_store(store)
    key_secret = _key_secret(opts["flags"], store=store, theme=theme)
    chain_crl_flag = opts["flags"].get("chain-crl")
    if chain_crl_flag:
        chain_crl_path = Path(chain_crl_flag)
        try:
            data = chain_crl_path.read_bytes()
        except OSError as exc:
            raise ValueError(f"Expected a readable --chain-crl file, got {chain_crl_path} ({exc.strerror})") from exc
        certs, crls = _pem_or_der_artifacts(data, chain_crl_path)
        if certs or not crls:
            raise ValueError(f"Expected only CRLs in --chain-crl {chain_crl_path}")
        for crl in crls:
            store.import_chain_crl(crl)
        print(theme.ok(f"imported {len(crls)} issuer CRL(s) from {chain_crl_path} into {store.chain_crl_path}"))
    store.publish_crl(validity_days=days, key_secret=key_secret)
    print(theme.ok(f"crl regenerated: {store.crl_path} (valid {store.crl_validity_days} days)"))


def _cmd_ocsp(args: list[str], *, store: CertificateStore | None, theme: Theme) -> None:
    opts = _parse_flags(args, command="ocsp")
    positional = opts["positional"]
    flags = opts["flags"]
    action = positional[0] if positional else "publish"
    if action not in {"disable", "publish", "url"}:
        raise ValueError(f"Expected ocsp publish|disable|url, got {action!r}")
    if len(positional) > (2 if action == "url" else 1):
        raise ValueError(f"Unexpected extra arguments: {' '.join(positional[1:])}")
    if action != "publish" and flags.keys() & {"days", "key-secret-file"}:
        raise ValueError("--days / --key-secret-file are only supported for ocsp publish")
    if action != "url" and "clear" in flags:
        raise ValueError("--clear is only supported for ocsp url")
    store = _require_store(store)
    if action == "url":
        if "clear" in flags:
            if len(positional) == 2:
                raise ValueError("Expected ocsp url URL or ocsp url --clear, not both")
            store.set_ocsp_url(None)
            print(theme.ok("OCSP URL cleared; new certificates carry no Authority Information Access"))
        elif len(positional) == 2:
            store.set_ocsp_url(positional[1])
            print(theme.ok(f"new certificates point at the OCSP responder {store.ocsp_url}"))
            print(theme.dim("certificates already issued keep what they were issued with"))
        else:
            print(store.ocsp_url or theme.dim("(no OCSP URL; new certificates carry no Authority Information Access)"))
        return
    if action == "disable":
        store.disable_ocsp()
        print(theme.ok(f"OCSP stapling disabled; removed {store.ocsp_dir}"))
        return
    days = _parse_ocsp_days(flags["days"]) if "days" in flags else None
    key_secret = _key_secret(flags, store=store, theme=theme)
    written = store.publish_ocsp(validity_days=days, key_secret=key_secret)
    print(
        theme.ok(
            f"published {len(written)} OCSP response(s) in {store.ocsp_dir} (valid {store.ocsp_validity_days} days)"
        )
    )
    for path in written:
        print(theme.dim(str(path)))
    print(theme.dim("every CRL publish (revoke, create, crl) now refreshes them; ocsp disable stops"))


def _cmd_encrypt_key(args: list[str], *, store: CertificateStore | None, theme: Theme) -> None:
    store = _require_store(store)
    opts = _parse_flags(args, command="encrypt-key")
    if opts["positional"]:
        raise ValueError("encrypt-key takes no positional arguments")
    if store.ca_key_encrypted:
        raise ValueError("The CA private key is already encrypted")
    key_secret = _required_key_secret(opts["flags"], store=store, theme=theme, confirm=True)
    store.encrypt_ca_key(key_secret)
    print(theme.ok(f"CA private key encrypted: {store.ca_key_path}"))
    if "key-secret-file" in opts["flags"]:
        _offer_to_remove_key_secret_file(Path(opts["flags"]["key-secret-file"]), theme)


def _cmd_decrypt_key(args: list[str], *, store: CertificateStore | None, theme: Theme) -> None:
    store = _require_store(store)
    opts = _parse_flags(args, command="decrypt-key")
    if opts["positional"]:
        raise ValueError("decrypt-key takes no positional arguments")
    if not store.ca_key_encrypted:
        raise ValueError("The CA private key is not encrypted")
    key_secret = _required_key_secret(opts["flags"], store=store, theme=theme)
    store.decrypt_ca_key(key_secret)
    print(theme.ok(f"CA private key decrypted: {store.ca_key_path}"))


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
    uris = get_certificate_uris(cert_pem)
    if uris:
        print(f"uris      {', '.join(uris)}")


def _print_csr_summary(summary: CsrSummary, theme: Theme) -> None:
    key = f"{summary.key_type} {summary.key_size}" if summary.key_size is not None else summary.key_type
    print(f"csr subject {summary.subject or '(empty)'}")
    if summary.sans:
        print(f"sans      {', '.join(summary.sans)}")
    print(f"key       {key}")
    print(f"signature {summary.signature_hash or 'unknown'}")
    print(f"public key sha256 {summary.public_key_fingerprint or 'unavailable'}")
    if summary.requested_extensions:
        print(theme.dim(f"requests  {', '.join(summary.requested_extensions)} (ignored when signing)"))
    if summary.problems:
        print(theme.error("status    refused: sign would reject this CSR"))
        for problem in summary.problems:
            print(theme.dim(f"          {problem}"))
    else:
        print(f"status    {theme.ok('signable')}")


def _check_file(
    path: Path,
    *,
    within: timedelta | None,
    by: datetime | None,
    ca_cert_pem: bytes | None,
    crl_pem: bytes | None,
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
        rows.append((name, check_certificate(cert_pem, within=within, by=by, ca_cert_pem=ca_cert_pem, crl_pem=crl_pem)))
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
    crl_pem: bytes | None,
    password: str | None,
    theme: Theme,
) -> list[tuple[str, CertificateStatus]]:
    """Check certificate, chain, CRL, and PKCS#12 files; directories are scanned one level deep."""
    rows: list[tuple[str, CertificateStatus]] = []
    for target in targets:
        if target.is_dir():
            for path in sorted(p for p in target.iterdir() if p.is_file() and p.suffix.lower() in _CHECK_SUFFIXES):
                try:
                    rows.extend(
                        _check_file(
                            path, within=within, by=by, ca_cert_pem=ca_cert_pem, crl_pem=crl_pem, password=password
                        )
                    )
                except ValueError as exc:
                    print(theme.dim(f"skipped {path}: {exc}"), file=sys.stderr)
        elif target.exists():
            rows.extend(
                _check_file(target, within=within, by=by, ca_cert_pem=ca_cert_pem, crl_pem=crl_pem, password=password)
            )
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


def _parse_crl_days(raw: str, flag: str) -> int:
    """Parse a CRL lifetime in days, bounded to 1..``MAX_STORE_CRL_VALIDITY_DAYS``."""
    try:
        days = int(raw.strip())
    except ValueError as exc:
        raise ValueError(f"Expected a whole number of days for {flag}, got {raw!r}") from exc
    if not 1 <= days <= MAX_STORE_CRL_VALIDITY_DAYS:
        raise ValueError(f"Expected {flag} between 1 and {MAX_STORE_CRL_VALIDITY_DAYS}, got {days}")
    return days


def _parse_ocsp_days(raw: str) -> int:
    """Parse ``ocsp --days``, bounded to 1..``MAX_OCSP_VALIDITY_DAYS``."""
    try:
        days = int(raw.strip())
    except ValueError as exc:
        raise ValueError(f"Expected a whole number of days for --days, got {raw!r}") from exc
    if not 1 <= days <= MAX_OCSP_VALIDITY_DAYS:
        raise ValueError(f"Expected --days between 1 and {MAX_OCSP_VALIDITY_DAYS}, got {days}")
    return days


def _parse_path_length(raw: str) -> int:
    if raw not in {"0", "1"}:
        raise ValueError(f"Expected --path-length 0 (sign leaves only) or 1 (also sign intermediate CAs), got {raw!r}")
    return int(raw)


def _parse_key_options(flags: dict[str, str]) -> tuple[KeyType, int | None]:
    """Parse ``--key-type`` / ``--key-size``; an omitted size means the library default."""
    raw_type = flags.get("key-type", DEFAULT_KEY_TYPE).strip().lower()
    if raw_type not in KEY_TYPES:
        raise ValueError(f"Expected --key-type in {', '.join(KEY_TYPES)}, got {flags['key-type']!r}")
    if "key-size" not in flags:
        return raw_type, None
    if raw_type == "ec-p256":
        raise ValueError("Expected no --key-size with --key-type ec-p256 (P-256 has a fixed size)")
    try:
        return raw_type, int(flags["key-size"].strip())
    except ValueError as exc:
        raise ValueError(f"Expected a whole number for --key-size, got {flags['key-size']!r}") from exc


def _parse_flags(args: list[str], *, command: str) -> _ParsedFlags:
    """Parse ``--flag value`` / ``--flag`` against ``COMMAND_FLAGS[command]`` and collect positionals.

    Repeatable flags (``--san``, ``--permit``, ``--kind``) accumulate in ``multi``. Switches
    (``--force``) never consume the following positional token.
    """
    specs = {flag.name: flag for flag in COMMAND_FLAGS[command]}
    positional: list[str] = []
    flags: dict[str, str] = {}
    multi: dict[str, list[str]] = {}
    i = 0
    while i < len(args):
        token = args[i]
        if token.startswith("--"):
            name = token[2:]
            spec = specs.get(name)
            if spec is None:
                raise ValueError(f"Unknown flag --{name}")
            if spec.value is None:
                value = ""
                i += 1
            elif i + 1 < len(args) and not args[i + 1].startswith("--"):
                value = args[i + 1]
                i += 2
            else:
                value = ""
                i += 1
            if not value and spec.value is not None and not spec.allow_empty:
                raise ValueError(f"Expected a non-empty value for --{name}")
            if spec.repeatable:
                multi.setdefault(name, []).append(value)
            else:
                flags[name] = value
            continue
        positional.append(token)
        i += 1
    return {"positional": positional, "flags": flags, "multi": multi}


def _require_one_positional(opts: _ParsedFlags, usage: str) -> str:
    """Return the single positional argument, refusing none or extras before anything is written."""
    positional = opts["positional"]
    if not positional:
        raise ValueError(f"Expected {usage}")
    if len(positional) > 1:
        raise ValueError(f"Unexpected extra arguments: {' '.join(positional[1:])} (expected {usage})")
    return positional[0]


def _safe_export_name(common_name: str) -> str:
    """Escape path separators for a default export filename.

    ``normalize_subject_attribute`` already rejects ``/`` and ``\\`` for
    newly issued certificates, but a hand-edited or legacy ``index.json``
    entry could still carry one — this keeps ``export pem``'s default
    output path a single component either way.
    """
    return common_name.replace("/", "_").replace("\\", "_")


def _write_secret_file(path: Path, data: str | bytes) -> None:
    """Write an export with mode 0600, refusing to write through a symlink at ``path``."""
    payload = data.encode() if isinstance(data, str) else data
    write_file_atomic(path, payload, mode=0o600)
