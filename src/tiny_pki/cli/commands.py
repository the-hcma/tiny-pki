"""Command table and help text for the tiny-pki REPL."""

from __future__ import annotations

COMMAND_HELP: tuple[tuple[str, str], ...] = (
    ("clear", "Clear the terminal screen."),
    ("completion", "Print or install bash/zsh/fish tab-completion scripts."),
    ("create", "Issue a certificate: create client|server <name> [options]."),
    ("crl", "Regenerate the CRL from revoked entries."),
    ("delete", "Remove a certificate from the store (revoked or --force)."),
    ("edit-mode", "Switch Emacs vs Vim keys: edit-mode emacs | vim."),
    ("exit", "Leave the REPL."),
    ("export", "Export pem|p12 for an identity."),
    ("help", "Show this list."),
    ("init", "Create a new CA in --store."),
    ("inspect", "Inspect a store identity or PEM path."),
    ("quit", "Leave the REPL (same as exit)."),
    ("renew-crl", "Alias for crl."),
    ("revoke", "Revoke an identity and regenerate the CRL."),
    ("show", "Show ca|certs|crl|<identity>."),
)

COMMANDS: tuple[str, ...] = tuple(sorted({name for name, _ in COMMAND_HELP}))

PKI_COMMANDS: frozenset[str] = frozenset(
    {
        "create",
        "crl",
        "delete",
        "export",
        "init",
        "inspect",
        "renew-crl",
        "revoke",
        "show",
    }
)
