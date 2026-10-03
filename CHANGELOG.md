# Changelog

All notable changes to tiny-pki are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/). Until 1.0, a minor release may change the API; such changes are called out under **Changed**.

## [1.0.0](https://github.com/the-hcma/tiny-pki/compare/v0.1.0...v1.0.0) (2026-10-03)


This release includes all 19 changes merged since v0.1.0, covering certificate enrollment, offline-root hierarchies, encrypted CA keys, revocation publishing, mutual TLS integration, documentation and maintenance.

### Breaking changes and upgrade notes

- The default CRL lifetime drops from 30 to 7 days for `generate_crl` and new stores. Schedule daily renewal and monitor it with `check --crl-renewal 1d`; use `crl --days 30` if your renewal schedule needs the previous window. Existing stores keep their configured lifetime, and stores without `ca/crldays` preserve their existing CRL's lifetime on the next publish. Store CRL lifetimes are now capped at 365 days; the low-level `generate_crl` API retains its 36500-day cap. ([#174](https://github.com/the-hcma/tiny-pki/pull/174))

### Library

- Sign client and server CSRs with `sign_client_csr` and `sign_server_csr`, so device, TPM, YubiKey and server private keys stay where they were generated. PEM and DER CSRs are supported; key and signature policy is checked, while identities and extensions remain under CA control. `inspect_csr` reports requested identities, key fingerprints and policy problems; server CSR SANs are accepted only when explicitly enabled. ([#155](https://github.com/the-hcma/tiny-pki/pull/155), [#158](https://github.com/the-hcma/tiny-pki/pull/158))

- Issue intermediate CAs with `generate_intermediate_ca_certificate` or `sign_intermediate_csr` under a root created with `path_length=1`, allowing the root key to remain offline. Intermediates inherit or narrow name constraints, cannot outlive their issuer and cannot sign further CAs. PKCS#12 bundles support the CA chain. ([#163](https://github.com/the-hcma/tiny-pki/pull/163))

- Sign OCSP responses with `generate_ocsp_response` and `generate_ocsp_response_for_certificate`, including good, revoked and unknown status, nonce handling and pre-signed stapling responses. Optional `ocsp_url` adds Authority Information Access to issued leaves; tiny-pki does not run an OCSP responder. ([#162](https://github.com/the-hcma/tiny-pki/pull/162))

- Accept PEM or DER certificates in inspection and certificate checks. `get_certificate_uris` exposes URI SANs, and `get_certificate_identity` returns the peer's CN, DNS names, IP addresses, URIs, serial and fingerprint in one call. ([#170](https://github.com/the-hcma/tiny-pki/pull/170))

- Add an optional URI SAN to client certificates, including SPIFFE identities, with URI normalization and CA URI name constraints via `permitted_subtrees` entries prefixed with `uri:`. Issuance enforces the permitted URI hosts. ([#171](https://github.com/the-hcma/tiny-pki/pull/171))

- Build mutual-TLS `ssl.SSLContext` objects from PEM bytes with the optional `tiny_pki.tls.server_context` and `client_context` helpers. They trust only the supplied CA, require TLS 1.2 or newer, support client-certificate policy and server-side leaf or full-chain CRL checking, and clean up temporary key files. ([#172](https://github.com/the-hcma/tiny-pki/pull/172))

- Add optional `crl_url` to leaf issuance for CRL Distribution Points, and `renewal_interval` to `check_crl` to flag CRLs that will expire before renewal or have less than twice the renewal interval in their lifetime. ([#174](https://github.com/the-hcma/tiny-pki/pull/174))

- Add `tiny_pki.secrets.encrypt_private_key_scrypt` and `decrypt_private_key_scrypt`, using a per-key salt and Scrypt-derived Fernet key, alongside the existing HKDF helpers. ([#152](https://github.com/the-hcma/tiny-pki/pull/152))

### Store and CLI

- Encrypt CA keys at initialization with `init --encrypt-key`, or migrate existing stores with `encrypt-key` and `decrypt-key`. Signing reads the secret from a prompt, `--key-secret-file`, `TINY_PKI_KEY_SECRET_FILE` or the systemd `tiny-pki-key` credential; read-only operations remain usable without it. Secrets are not command-line arguments. Removal of an explicitly supplied staging secret file is opt-in and protects configured credential sources. ([#152](https://github.com/the-hcma/tiny-pki/pull/152))

- Recommend CA-key encryption in CLI help and warn after plaintext CA creation with a store-specific migration command, without silently changing the plaintext default. ([#178](https://github.com/the-hcma/tiny-pki/pull/178))

- Enroll device and server keys with `sign client|server NAME --csr PATH`; `inspect` recognizes CSRs. Signed certificates can be exported without a stored private key, and replacement and revocation follow the existing store policies. ([#155](https://github.com/the-hcma/tiny-pki/pull/155), [#158](https://github.com/the-hcma/tiny-pki/pull/158))

- Create a root with `init --path-length 1`, initialize an issuing CA with `init --intermediate-of`, or sign an external intermediate CSR with `sign intermediate`. Stores publish the CA chain and combined chain CRLs; `crl --chain-crl PATH` imports issuer CRLs with signature and rollback checks. ([#163](https://github.com/the-hcma/tiny-pki/pull/163))

- Publish OCSP stapling files with `ocsp [publish]`, configure their lifetime with `--days`, and set the advertised responder with `ocsp url`. Once enabled, responses refresh on each CRL publish; `ocsp disable` stops publishing. ([#162](https://github.com/the-hcma/tiny-pki/pull/162))

- Issue client URI identities with `create client` or `sign client --uri-san`, and constrain them when initializing a CA with `--permit-uri`. ([#171](https://github.com/the-hcma/tiny-pki/pull/171))

- Export separate certificate, private-key and CA-chain files with `export pem --cert-out --key-out --ca-out`, while retaining the combined PEM form. Destinations are validated and files are staged with rollback on failed installation. ([#173](https://github.com/the-hcma/tiny-pki/pull/173))

- Configure `crl hook COMMAND` to reload TLS services after CRL or OCSP publication, with a 120-second timeout and explicit failure reporting. Configure an opt-in CRL Distribution Points URL with `crl url`; it applies to newly issued certificates, not existing ones. Serve a DER copy of the issuing CA's own CRL at that URL. `check --crl-renewal` monitors renewal headroom. ([#174](https://github.com/the-hcma/tiny-pki/pull/174))

### Documentation and maintenance

- Expand API, CLI, store, defaults, monitoring and security documentation for the new workflows, including CSR enrollment, protected CA-key secrets, offline roots, nginx OCSP stapling, URI identities, TLS contexts, split PEM exports and daily CRL renewal. ([#152](https://github.com/the-hcma/tiny-pki/pull/152), [#155](https://github.com/the-hcma/tiny-pki/pull/155), [#158](https://github.com/the-hcma/tiny-pki/pull/158), [#162](https://github.com/the-hcma/tiny-pki/pull/162), [#163](https://github.com/the-hcma/tiny-pki/pull/163), [#170](https://github.com/the-hcma/tiny-pki/pull/170), [#171](https://github.com/the-hcma/tiny-pki/pull/171), [#172](https://github.com/the-hcma/tiny-pki/pull/172), [#173](https://github.com/the-hcma/tiny-pki/pull/173), [#174](https://github.com/the-hcma/tiny-pki/pull/174), [#178](https://github.com/the-hcma/tiny-pki/pull/178))

- Add a comparison with the OpenBao PKI engine, integration guidance and deliberate non-goals. ([#177](https://github.com/the-hcma/tiny-pki/pull/177))

- Remove the my-tracks relicensing note from the README; the package remains MIT licensed. ([#148](https://github.com/the-hcma/tiny-pki/pull/148))

- Sync unwrapped agent-rule templates and subsequent formatting, signing and stacking guidance fixes from repository-helpers; add a GitHub Copilot instructions pointer to the canonical agent rules. ([#149](https://github.com/the-hcma/tiny-pki/pull/149), [#151](https://github.com/the-hcma/tiny-pki/pull/151), [#176](https://github.com/the-hcma/tiny-pki/pull/176))

- Remove the bootstrap version override after v0.1.0 so Release Please selects subsequent versions from Conventional Commits. ([#147](https://github.com/the-hcma/tiny-pki/pull/147))

- Update the SHA-pinned `astral-sh/setup-uv` action from v10.1.0 to v10.2.0 in CI, CVE checks and publishing, and update locked `wcwidth` from 0.8.4 to 0.9.1. Python remains >=3.12 and the minimum `cryptography` version remains 50.0.1. ([#165](https://github.com/the-hcma/tiny-pki/pull/165), [#179](https://github.com/the-hcma/tiny-pki/pull/179))

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
