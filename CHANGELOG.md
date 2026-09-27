# Changelog

All notable changes to tiny-pki are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/). Until 1.0, a minor release may change the API; such changes are called out under **Changed**.

## [0.1.0] - 2026-09-27

The first release on PyPI. It supports Python 3.12 and newer, and needs `cryptography` 50.0.1 or newer; the `cli` extra adds `prompt-toolkit`.

### Library

- Issue a CA, client certificates (`CLIENT_AUTH`) and server certificates (`SERVER_AUTH`), with RSA (2048, 3072 or 4096 bits) or ECDSA P-256 keys. Leaves may use a different key type from their CA.
- Name Constraints on the CA (`permitted_subtrees`). A leaf must fall inside a permitted subtree for every name type it uses.
- Validity and key-size defaults that follow current practice, with caps on leaf validity and `max_leaf_validity_days` for clamping presets in a UI.
- Common names and organizations are validated, and SANs normalized, including IDNs and IPv4-mapped addresses. DN special characters in a CN are refused unless explicitly allowed.
- CRLs with a monotonic `CRLNumber` and an `AuthorityKeyIdentifier`, plus checks that stop a stale or rolled-back CRL from hiding revocations.
- PKCS#12 bundles protected by AES-256, with a legacy 3DES mode for older keychains. Passwords must be at least 16 bytes.
- Expiry and validity checks for certificates and CRLs.
- Optional `tiny_pki.secrets` helpers that encrypt private keys with Fernet, using an HKDF-derived key.
- Input and policy rejections raise `TinyPkiError`, a subclass of `ValueError`. Advisories are issued as `TinyPkiWarning`, and only once issuance has succeeded.
- Ships a `py.typed` marker.

### Store and CLI

- `tiny-pki` runs one command and exits, or opens a REPL with no command. The commands are `init`, `create`, `list`, `show`, `inspect`, `export`, `revoke`, `delete`, `crl` (also `renew-crl`), `check` and `completion`.
- The store is a directory with a CA, an index and per-leaf files, plus a key-free `public/` directory holding the CA certificate and CRL for TLS servers. The CRL lifetime is saved in the store.
- Store writes are atomic, serialized on an exclusive lock, and refuse symlinks anywhere on the write path. Exports are written with mode `0600`.
- `create client --keep-previous` rotates a client certificate without revoking the current one until the device has switched.
- `revoke` and `delete` accept `--dry-run`. Lookups that match more than one certificate are refused, and `delete --force` revokes before deleting.
- `check` reports expired, expiring, revoked and untrusted certificates and CRLs, from the store or from files (PEM, DER, chains, CRLs, PKCS#12 bundles, directories). It exits with Nagios-style codes and can print JSON.
- `export p12` takes the password from a prompt or `--password-file`, never as an argument.
- Unknown flags are rejected before anything is written.
- Shell completion for bash, zsh and fish (`completion SHELL --install`) and in the REPL covers commands, each command's flags and flag values. All of these come from one flag table, which `help COMMAND` and [docs/cli.md](https://github.com/the-hcma/tiny-pki/blob/main/docs/cli.md) also follow.
- `tiny-pki --version` prints the version and the commit it was built from.

### Security

- Reviewed before release; the findings and their fixes are summarized in [SECURITY.md](https://github.com/the-hcma/tiny-pki/blob/main/SECURITY.md).

[0.1.0]: https://github.com/the-hcma/tiny-pki/releases/tag/v0.1.0
