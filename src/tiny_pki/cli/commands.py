"""Command table, per-command flags, and help text for the tiny-pki CLI.

``COMMAND_FLAGS`` is the single source for which flags each verb accepts: the
flag parser, ``help <command>``, the REPL completer, and the bash/zsh/fish
completion scripts all read it, and ``docs/cli.md`` is tested against it.
"""

from __future__ import annotations

from dataclasses import dataclass

from tiny_pki.constants import KEY_TYPES
from tiny_pki.store import CHECK_KINDS


@dataclass(frozen=True)
class Flag:
    """One ``--name`` option of a command.

    ``value`` is the placeholder shown in help (``None`` for a switch that takes
    no value). ``choices`` lists the accepted values for completion, ``path``
    marks values that name a file, ``repeatable`` flags accumulate, and
    ``allow_empty`` lets ``--name`` without a value fall back to the default.
    """

    name: str
    help: str
    value: str | None = None
    choices: tuple[str, ...] = ()
    path: bool = False
    repeatable: bool = False
    allow_empty: bool = False

    @property
    def option(self) -> str:
        return f"--{self.name}"


_DAYS = Flag("days", "validity in days (default 397 for clients, 90 for servers)", value="N", allow_empty=True)
_KEY_SIZE = Flag(
    "key-size",
    "RSA key size in bits (default 4096 for the CA, 3072 for leaves)",
    value="BITS",
    choices=("2048", "3072", "4096"),
)
_KEY_TYPE = Flag("key-type", "key algorithm (default rsa)", value="TYPE", choices=KEY_TYPES, allow_empty=True)
_ORG = Flag("org", "organization (O) in the subject", value="NAME", allow_empty=True)
_DRY_RUN = Flag("dry-run", "show what would change and write nothing")
_JSON = Flag("json", "machine-readable JSON output")
_PASSWORD_FILE = Flag("password-file", "read the PKCS#12 password from this file", value="PATH", path=True)
_KEY_SECRET_FILE = Flag(
    "key-secret-file", "read the CA-key secret from this file or systemd credential", value="PATH", path=True
)

COMMAND_FLAGS: dict[str, tuple[Flag, ...]] = {
    "check": (
        Flag("by", "alert on anything expiring by this date", value="YYYY-MM-DD"),
        Flag("ca", "CA certificate to verify file targets against", value="PATH", path=True),
        Flag("crl", "CRL to check file targets against", value="PATH", path=True),
        Flag("include-revoked", "also report revoked store entries"),
        _JSON,
        Flag(
            "kind",
            "only check this kind (repeatable)",
            value="KIND",
            choices=tuple(sorted(CHECK_KINDS)),
            repeatable=True,
        ),
        _PASSWORD_FILE,
        Flag("quiet", "print only rows that need attention"),
        Flag("within", "alert window in days (default: a third of each lifetime)", value="DAYS"),
    ),
    "create": (
        Flag("allow-dn-special-chars", 'allow , + = " < > ; or a leading # in the CN'),
        Flag("allow-long-validity", "allow validity beyond the 200 / 825 day caps"),
        _DAYS,
        _KEY_SECRET_FILE,
        Flag("keep-previous", "client only: keep the previous certificate live for rotation"),
        _KEY_SIZE,
        _KEY_TYPE,
        Flag("no-cn-san", "server only: do not add the CN to the SANs"),
        _ORG,
        Flag("san", "server only: DNS name or IP address (repeatable)", value="NAME", repeatable=True),
        Flag("yes", "server only: add the CN to the SANs without asking"),
    ),
    "crl": (_KEY_SECRET_FILE, Flag("days", "change the stored CRL lifetime (1-365)", value="N")),
    "decrypt-key": (_KEY_SECRET_FILE,),
    "delete": (_KEY_SECRET_FILE, Flag("force", "revoke an active certificate first"), _DRY_RUN),
    "encrypt-key": (_KEY_SECRET_FILE,),
    "export": (
        Flag("legacy", "p12 only: 3DES / SHA-1 encryption for old Android and Apple keychains"),
        Flag("out", "output file", value="PATH", path=True),
        _PASSWORD_FILE,
    ),
    "init": (
        Flag("cn", 'CA common name (default "Private CA")', value="NAME", allow_empty=True),
        Flag("crl-days", "CRL lifetime in days (1-365, default 30)", value="N"),
        Flag("days", "CA validity in days (default 3650)", value="N", allow_empty=True),
        Flag("encrypt-key", "encrypt the CA private key at rest"),
        _KEY_SECRET_FILE,
        _KEY_SIZE,
        _KEY_TYPE,
        _ORG,
        Flag("permit", "name constraint: DNS suffix or IP network (repeatable)", value="NAME", repeatable=True),
    ),
    "inspect": (),
    "list": (_JSON,),
    "revoke": (_KEY_SECRET_FILE, _DRY_RUN),
    "show": (),
    "sign": (
        Flag("accept-csr-sans", "server only: also include the SANs the CSR requests, without asking"),
        Flag("allow-dn-special-chars", 'allow , + = " < > ; or a leading # in the CN'),
        Flag("allow-long-validity", "allow validity beyond the 200 / 825 day caps"),
        Flag("csr", "the certificate signing request (PEM or DER)", value="PATH", path=True),
        _DAYS,
        Flag("keep-previous", "client only: keep the previous certificate live for rotation"),
        _KEY_SECRET_FILE,
        Flag("no-cn-san", "server only: do not add the CN to the SANs"),
        _ORG,
        Flag("out", "also write the issued certificate to this file", value="PATH", path=True),
        Flag("san", "server only: DNS name or IP address (repeatable)", value="NAME", repeatable=True),
        Flag("yes", "server only: add the CN to the SANs without asking"),
    ),
}
COMMAND_FLAGS["renew-crl"] = COMMAND_FLAGS["crl"]
COMMAND_FLAGS["completion"] = (
    Flag("force", "with --install: overwrite a different existing script"),
    Flag("install", "write the script to the per-user completion directory"),
    _JSON,
)

COMMAND_USAGE: dict[str, str] = {
    "check": "check [PATH...]",
    "completion": "completion bash|zsh|fish [--install] [--force] [--json]",
    "create": "create client|server NAME",
    "crl": "crl",
    "decrypt-key": "decrypt-key",
    "delete": "delete NAME|0xSERIAL",
    "edit-mode": "edit-mode [emacs|vim]",
    "encrypt-key": "encrypt-key",
    "export": "export pem|p12 NAME",
    "help": "help [COMMAND]",
    "init": "init",
    "inspect": "inspect NAME|PATH",
    "list": "list [ca|certs|clients|servers|revoked]",
    "renew-crl": "renew-crl",
    "revoke": "revoke NAME|0xSERIAL",
    "show": "show ca|certs|crl|NAME",
    "sign": "sign client|server NAME --csr PATH",
}

COMMAND_HELP: tuple[tuple[str, str], ...] = (
    (
        "check",
        "Flag expired, expiring, revoked or untrusted certificates and CRLs in the store or in files.",
    ),
    ("clear", "Clear the terminal screen."),
    ("completion", "Print or install bash/zsh/fish tab-completion scripts."),
    ("create", "Issue a client or server certificate."),
    ("crl", "Regenerate the CRL from revoked entries; --days N changes the stored CRL lifetime."),
    ("decrypt-key", "Decrypt the CA private key in place."),
    ("delete", "Remove a revoked certificate's files; --force revokes an active one first; --dry-run previews."),
    ("edit-mode", "Switch Emacs vs Vim keys: edit-mode emacs | vim."),
    ("encrypt-key", "Encrypt the CA private key in place."),
    ("exit", "Leave the REPL."),
    ("export", "Export pem|p12 for an identity."),
    ("help", "Show this list, or help <command> for its usage and flags."),
    ("init", "Create a new CA in --store."),
    ("inspect", "Inspect a store identity, a certificate file, or a CSR file."),
    ("list", "List ca|clients|servers|revoked|certs (optional --json)."),
    ("quit", "Leave the REPL (same as exit)."),
    ("renew-crl", "Alias for crl."),
    ("revoke", "Revoke an identity and regenerate the CRL; --dry-run previews."),
    ("show", "Show ca|certs|crl|<identity> (aliases list categories)."),
    ("sign", "Issue a client or server certificate for a CSR; the private key stays where it was made."),
)

COMMANDS: tuple[str, ...] = tuple(sorted({name for name, _ in COMMAND_HELP}))

POSITIONAL_CHOICES: dict[str, tuple[str, ...]] = {
    "completion": ("bash", "fish", "zsh"),
    "create": ("client", "server"),
    "edit-mode": ("emacs", "vim"),
    "export": ("p12", "pem"),
    "help": COMMANDS,
    "list": ("ca", "certs", "clients", "revoked", "servers"),
    "show": ("ca", "certs", "clients", "crl", "revoked", "servers"),
    "sign": ("client", "server"),
}

PKI_COMMANDS: frozenset[str] = frozenset(
    {
        "check",
        "create",
        "crl",
        "decrypt-key",
        "delete",
        "encrypt-key",
        "export",
        "init",
        "inspect",
        "list",
        "renew-crl",
        "revoke",
        "show",
        "sign",
    }
)
