"""Command table and help text for the tiny-pki REPL."""

from __future__ import annotations

COMMAND_HELP: tuple[tuple[str, str], ...] = (
    (
        "check",
        "Flag expired/expiring/revoked certs and CRLs: check [PATH... [--ca CA] [--crl CRL]] [--within DAYS] [--json].",
    ),
    ("clear", "Clear the terminal screen."),
    ("completion", "Print or install bash/zsh/fish tab-completion scripts."),
    ("create", "Issue a certificate: create client|server <name> [options]."),
    ("crl", "Regenerate the CRL from revoked entries."),
    ("delete", "Remove a revoked certificate's files; --force revokes an active one first."),
    ("edit-mode", "Switch Emacs vs Vim keys: edit-mode emacs | vim."),
    ("exit", "Leave the REPL."),
    ("export", "Export pem|p12 for an identity."),
    ("help", "Show this list."),
    ("init", "Create a new CA in --store."),
    ("inspect", "Inspect a store identity or PEM path."),
    ("list", "List ca|clients|servers|revoked|certs (optional --json)."),
    ("quit", "Leave the REPL (same as exit)."),
    ("renew-crl", "Alias for crl."),
    ("revoke", "Revoke an identity and regenerate the CRL."),
    ("show", "Show ca|certs|crl|<identity> (aliases list categories)."),
)

COMMANDS: tuple[str, ...] = tuple(sorted({name for name, _ in COMMAND_HELP}))

PKI_COMMANDS: frozenset[str] = frozenset(
    {
        "check",
        "create",
        "crl",
        "delete",
        "export",
        "init",
        "inspect",
        "list",
        "renew-crl",
        "revoke",
        "show",
    }
)
