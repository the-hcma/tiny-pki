# Security review — Grok 4.7 (Cursor)

- **Date:** 2026-09-26
- **Model / agent:** Grok 4.7, via a Cursor agent subagent (autonomous, against a source snapshot)
- **Commit reviewed:** `074cfa0afe2923afc75c67dda4d0f7e336e5024b` (`main`)
- **Scope:** full-repo review per issue #34's brief — crypto correctness, input handling, the filesystem store, CLI, supply chain/CI, and docs.
- **Method:** Read every module under `src/tiny_pki/` (including `cli/`), `tests/` for intended behavior, `docs/`, `SECURITY.md`, `README.md`, `pyproject.toml`, `uv.lock`, and `.github/workflows/*` plus `.github/ci/*`. Did not use git history, GitHub, or the web, and did not read `docs/security-review/`. Confirmed findings with `uv run` against `mktemp -d` stores and OpenSSL 3.6.4. Script: `.poc/repro.py`.

---

## Findings

### 1. [High] `export` follows symlinks and writes private keys to the target

**Where:** `src/tiny_pki/cli/handlers.py` `_cmd_export` (default PEM path and `--out`), `_write_secret_file` (opens with `O_CREAT|O_TRUNC` and no `O_NOFOLLOW`, then `chmod`).

**Issue:** Store writes for `ca.key`, the CRL, and `index.json` refuse a pre-existing symlink. Export does not. `export pem <cn>` writes `{cn}.pem` in the current directory (or whatever `--out` is). `open` follows a symlink, so the leaf certificate and private key are written to the link target. `chmod 0600` runs only after the bytes are written, and it follows the symlink too: if the target is owned by someone else, `chmod` fails and the mode the attacker chose is left in place.

**Impact:** A local user who can create a symlink where the operator exports (for example `/tmp/alice.pem` → an attacker-owned mode `0666` file, or a link onto `ca.key` / `authorized_keys`) gets the leaf private key or clobbers a file the operator can write. No store write access is required. `export p12 --out` uses the same helper.

**Reproduction:** `.poc/repro.py` (section `export pem follows symlink`). Observed: `export pem alice` from a directory where `alice.pem` was a symlink printed `wrote alice.pem`, and the link target contained `PRIVATE KEY` (2904 bytes).

**Recommendation:** Open the destination with `O_NOFOLLOW` (and refuse an existing symlink the way `_open_new_file` does). Write to a new file in the destination directory and `rename` it into place so a symlink cannot be followed.

### 2. [Medium] An IP-only name constraint still yields a server certificate for a public DNS name

**Where:** `src/tiny_pki/issue.py` `_enforce_name_constraints` (DNS and IP are enforced only when that type is present); `src/tiny_pki/cli/handlers.py` `_confirm_cn_in_sans` (non-TTY or `--yes` adds the CN as a SAN) and `_cmd_create`.

**Issue:** RFC 5280 name constraints apply only to the name types listed. A CA created with `--permit 192.168.0.0/16` and no DNS suffix does not constrain DNS SANs. Non-interactive `create server` (stdin is not a TTY, which is the normal case for scripts and `uv run`) appends a host-like CN to the SANs and exits 0. The stderr warning does not fail the command. `docs/security.md` says that after `permitted_subtrees` are set, a stolen CA key cannot impersonate public sites. That is true only when every name type the operator cares about is constrained. `docs/api.md` mentions the DNS-only direction (IP SANs stay open) and not this one.

**Impact:** The operator, or anyone who later holds `ca.key`, can mint a `serverAuth` certificate for an arbitrary website. OpenSSL 3.6.4 verifies that certificate against the IP-constrained CA. Devices that trust the CA will accept it for that DNS name. The library quick start in `README.md` does not set `permitted_subtrees` at all; the CLI quick start does set both DNS and IP, which is the safe pattern.

**Reproduction:**

```text
tiny-pki --store "$S" init --cn "IP CA" --key-size 2048 --permit 192.168.0.0/16
tiny-pki --store "$S" create server google.com --san 192.168.1.10 --key-size 2048
# stderr: Added common_name 'google.com' to the SANs as 'google.com'
# SAN: IP:192.168.1.10, DNS:google.com
openssl verify -CAfile "$S/ca/ca.crt" "$S/servers/google.com-"*.crt
# OK
openssl x509 -in "$S/ca/ca.crt" -noout -ext nameConstraints
# Permitted: IP:192.168.0.0/255.255.0.0
```

**Recommendation:** If the CA has any name constraint, refuse a DNS SAN unless a DNS permitted subtree is present, and refuse an IP SAN unless an IP permitted subtree is present (stricter than RFC 5280, which is what a private CA installed device-wide wants). At minimum, do not auto-add the CN when it is not covered by a DNS constraint, and correct `docs/security.md`.

### 3. [Medium] Lookup treats a common name and a hex serial as the same key

**Where:** `src/tiny_pki/store.py` `CertificateStore.get_certificate`. `revoke`, `delete`, `export`, `show`, and `inspect` all resolve identities through it.

**Issue:** A needle matches when it equals the common name (case-insensitive) **or** the hex serial (`0x` optional). If both an older certificate's serial and a newer certificate's CN match, the first **live** entry in index order wins. Serials are 159-bit hex and fit in the 64-character CN limit, and `list` prints them.

**Impact:** Someone who can choose a CN (the operator, or an app that issues from user-supplied names) sets it to another certificate's serial. `revoke <serial>` then revokes the older certificate and leaves the new one active. The CLI prints the older CN, which a human can notice; a script that revokes by serial will not. `export` / `delete` have the same ambiguity.

**Reproduction:** `.poc/repro.py` section `CN collides with another serial`. After `create client alice` (serial `1482daed…`) and `create client 1482daed…`, `revoke 1482daed…` printed `revoked alice`. Index afterwards: `alice` revoked, the certificate whose CN is that serial still active.

**Recommendation:** If the needle equals any stored serial, select only that serial. If it matches both a serial and a different CN, refuse as ambiguous instead of picking the first live row.

### 4. [Medium] A rolled-back CRL still looks healthy, and revoked certificates are reported ok

**Where:** `src/tiny_pki/check.py` `check_certificate` (a listed serial is revoked; `nextUpdate` is not consulted). `src/tiny_pki/cli/handlers.py` `_check_store` (any CRL that is not `UNTRUSTED`, including `EXPIRED`, is used) and `_store_trust_anchors`. `docs/monitoring.md` says `--include-revoked` leaves "report revoked".

**Issue:** Revocation status comes only from the CRL bytes, not from `index.json`. A CRL whose `nextUpdate` is still in the future is treated as proof that missing serials are not revoked, even when the index marks them revoked. An expired CRL is also treated as proof of non-revocation by `check_certificate` (`status=ok`, no reasons). The store-wide check fails closed on an expired CRL only because the CRL row itself is included; `--kind client` (or a caller that looks only at the leaf) does not get that signal.

**Impact:** Anyone who can replace `ca/crl.pem` with an older, still-unexpired CRL signed by this CA (the owner restoring a backup, or a publisher of the CRL that is not the `ca.key` file) un-revokes certificates. `tiny-pki check` stays exit 0, so the monitoring recipe does not catch it. OpenSSL/`nginx` with `ssl_crl` will accept the previously revoked client. `--include-revoked` reports that client as `ok`, which contradicts the docs. `crl.pem` is mode `0644`, so a local reader can snapshot it before the revocation and put it back if they can write the `ca/` directory.

**Reproduction:** `.poc/repro.py` section `CRL rollback vs tiny-pki check`. After `revoke dave`, `openssl verify -crl_check` failed with `certificate revoked`. After writing the pre-revoke CRL back, the same verify printed `OK`, `tiny-pki check --within 0` exited 0, and `check --include-revoked` listed `dave` as `ok`. Separately, `check_certificate` of a live cert against an expired empty CRL returned `status=ok`.

**Recommendation:** When checking the store, treat every index serial with `revoked_at` set as revoked even if the CRL omits it, and fail the check if the CRL's set is not a superset of the index. Do not treat a CRL past `nextUpdate` as evidence that a serial is unrevoked (report the leaf as unknown / critical, or ignore that CRL). Persist `crlNumber` (finding 11) so a regression is detectable.

### 5. [Low] `delete --force` drops the serial from the CRL

**Where:** `src/tiny_pki/store.py` `delete_certificate` (active entries are removed from the index, not tombstoned). `src/tiny_pki/cli/handlers.py` `_cmd_delete` regenerates the CRL from `revoked_entries()` afterwards. `docs/security.md` says `delete` removes the on-disk key after revocation.

**Issue:** `--force` is documented as the alternative to revoking first. It deletes the files and then publishes a CRL that does not contain that serial. A copy already exported remains valid until it expires.

**Impact:** An operator who "deletes" a compromised client with `--force` (the error text offers this instead of revoke) leaves relying parties trusting that certificate. `revoke` does the right thing and was confirmed with OpenSSL (`certificate revoked`).

**Reproduction:** `.poc/repro.py` section `delete --force omits serial from CRL`. After `delete bob --force`, `openssl crl -text` printed `No Revoked Certificates` and `openssl verify -crl_check` of the exported cert printed `OK`.

**Recommendation:** Make `--force` revoke (tombstone + CRL) and then delete the files. If a true forget-without-revocation path is required, give it a separate flag and say in the help text that existing copies stay valid.

### 6. [Low] Leaf and bundle writes still follow an in-store symlink onto `ca.key`

**Where:** `src/tiny_pki/store.py` `add_certificate` (`cert_path.write_bytes`, then `_write_secret` on the path returned by `_path_under_root`) and `write_bundle`. Contrast `_validated_write_path`, used by `write_ca`, `write_crl`, and the index temp file.

**Issue:** `_path_under_root` rejects a symlink whose **target** is outside the store, then returns the resolved path. A symlink that stays inside the store (leaf path → `ca/ca.key`) is followed. `write_bytes` / `_write_secret` then overwrite the target. `O_NOFOLLOW` never sees the original symlink. CLI serials are random, so planting the leaf name in advance is impractical; `write_bundle` uses the serial already stored in the index, which is not.

**Impact:** A process that can create files under `bundles/` or `clients/` but cannot open mode-`0600` `ca.key` can still destroy the CA key by pointing the next bundle path at it. On a default mode-`0755` directory that process is the owner, who can already unlink `ca.key`. The hole matters when the directory is writable by someone else (umask `000` or `002` with a shared group; see finding 7) and the key file itself is not.

**Reproduction:** `.poc/repro.py`. `write_bundle` with `bundles/<cn>-<serial>.p12` → `ca.key` succeeded and `ca.key` started with `NOT-A-KEY`. `add_certificate` with `clients/alice-1.crt` → `ca.key` succeeded and `ca.key` became `CERTDATA`. The outside-store symlink case is already rejected (covered by tests).

**Recommendation:** Resolve leaf and bundle paths with `_validated_write_path` (reject a symlink at any component) and write through that un-resolved path with `O_NOFOLLOW`.

### 7. [Low] Store directories are created with the process umask

**Where:** `src/tiny_pki/store.py` `ensure_layout` / `mkdir`. Secrets use mode `0600` from `open`, which is correct. Directories and `index.json` / `crl.pem` / `ca.crt` do not get an explicit mode.

**Issue:** With umask `022` the store is mode `0755` and `index.json` / `crl.pem` are `0644`. With umask `000` the store is mode `0777` while `ca.key` stays `0600`. Directory write lets another user replace `index.json` or `crl.pem` and plant the symlinks in finding 6, without being able to read the key.

**Impact:** On a shared host with a permissive umask, another local user can roll back the CRL (finding 4) or point an index `key_path` at `ca/ca.key` (finding 8) and wait for the owner to `export`.

**Reproduction:** `.poc/repro.py` section `store modes`. After a normal create: directory `0755`, key `0600`, index `0644`. After `umask 0`: directory `0777`, key still `0600`.

**Recommendation:** `mkdir` with mode `0700` (and `chmod` the existing root when opening it). Create `index.json` as `0600` as well; it names every client.

### 8. [Low] A tampered index `key_path` makes `export` copy `ca.key`

**Where:** `src/tiny_pki/store.py` `_entry_from_dict` / `_read_index` (any relative path that stays under the root is accepted). `src/tiny_pki/cli/handlers.py` `_cmd_export` reads `key_path` and writes it into the PEM or PKCS#12.

**Issue:** Paths are checked for escape, not for staying under `clients/` or `servers/`. `key_path: "ca/ca.key"` is valid.

**Impact:** Combined with directory write (finding 7) or a confused owner, the next `export pem alice` writes the CA private key into the file that will be handed to a device. Reproduced: export contained the exact `ca.key` PEM. The owner can already `cat ca.key`; the extra step is sending it out labeled as the leaf.

**Reproduction:** `.poc/repro.py` section `tampered index exports CA key`. Set the alice entry's `key_path` to `ca/ca.key`, then `export pem alice --out …`. `export contains CA private key=True`.

**Recommendation:** Allow `cert_path` / `key_path` only under `clients/` or `servers/` (and bundle writes only under `bundles/`), and reject a path whose final component is `ca.key`.

### 9. [Low] A leading dot on `--permit` is stripped, so the apex is included

**Where:** `src/tiny_pki/issue.py` `_permitted_subtree` (`normalize_dns_name(text.lstrip("."))`). Enforcement of an already-encoded leading dot is correct (`_dns_within`, and `tests/test_ca_constraints.py` `test_leading_dot_constraint_excludes_apex`).

**Issue:** OpenSSL's `DNS:.example.com` means "subdomains only". tiny-pki accepts `.example.com` and stores `example.com`, which also permits the apex. There is no error.

**Impact:** An operator who copies OpenSSL name-constraint syntax silently permits the bare name they were trying to exclude. Reproduced: permitted subtree stored as `DNSName('example.com')`, and a server certificate for `example.com` was issued.

**Recommendation:** Reject a leading dot with a message that the suffix includes the apex, or preserve the leading dot in the extension.

### 10. [Low] An IPv4 exclusion does not cover the IPv4-mapped IPv6 form

**Where:** `src/tiny_pki/issue.py` `_address_in` (requires `address.version == network.version`) and `_enforce_name_constraints`.

**Issue:** Excluded `10.0.0.0/8` rejects `10.1.2.3` and allows `::ffff:10.1.2.3`. OpenSSL 3.6.4 then verifies that leaf (`leaf.crt: OK`). The mapped form is a different GeneralName, so this matches a literal reading of RFC 5280; stacks that treat `::ffff:10.1.2.3` as `10.1.2.3` will not.

**Impact:** A CA that excludes an IPv4 range can still issue a server certificate for the mapped address of a host inside that range. Only matters for clients that connect to the mapped form.

**Reproduction:** `.poc/repro.py` section `ipv4-mapped vs excluded network`, then `openssl verify` (follow-up): `10.1.2.3` rejected by the library; `::ffff:10.1.2.3` issued; OpenSSL verify `OK`.

**Recommendation:** When checking an IPv4-mapped IPv6 SAN, also apply IPv4 constraints to the embedded address (and the reverse when the constraint itself is mapped).

### 11. [Low] The CLI never persists `crlNumber`

**Where:** `src/tiny_pki/revoke.py` `generate_crl` (default is microseconds since the epoch). Every CLI caller (`_cmd_revoke`, `_cmd_create`, `_cmd_delete`, `_cmd_crl`) omits `crl_number`. `docs/defaults.md` says a monotonic number lets clients discard older CRLs.

**Issue:** Nothing in the store records the last number. A backward clock step mints a smaller `crlNumber` than the CRL already published. The library documents this and offers a counter; the CLI cannot pass one.

**Impact:** A relying party that ignores a CRL with a lower number keeps the previous CRL and misses newer revocations until that CRL's `nextUpdate`. nginx reloads the file and does not track the number, so this is limited to clients that do.

**Reproduction:** not reproduced — reasoning only (call sites pass no `crl_number`; the default is `datetime.now`).

**Recommendation:** Store the last `crlNumber` in `index.json` (or beside the CRL) and always pass `last + 1`.

### 12. [Low] Secret and CRL writes truncate in place

**Where:** `src/tiny_pki/store.py` `_write_secret`, `_write_plain`, `add_certificate` (`Path.write_bytes`). The index is the exception: temp file plus `replace`.

**Issue:** `O_TRUNC` destroys the previous `ca.key` or `crl.pem` before the new bytes are durable, and there is no `fsync` before rename of the index either. A crash mid-`write_ca` can leave a short key. A crash after leaf files are written and before `_write_index` leaves an orphan key that the index does not track. A reader (nginx reload) can observe a truncated CRL.

**Impact:** Availability of the CA key and a window where revocation state on disk does not match the index. Not an attacker-controlled bypass by itself.

**Reproduction:** not reproduced — reasoning only (flags are `O_WRONLY|O_CREAT|O_TRUNC` on the final path).

**Recommendation:** Write secrets and the CRL to a temporary file in the same directory, `fsync`, then `rename` over the destination (and keep the `O_NOFOLLOW` checks).

### 13. [Low] `TINY_PKI_GIT_SHA` is printed without a hex check

**Where:** `src/tiny_pki/version.py` `_normalize_commit` (strip, then at most 12 characters). `format_cli_version_line` prints it. The same shape is used for `TINY_PKI_EMBED_COMMIT` at build time (`scripts/embed_build_metadata` stores it with `repr`, so the generated file stays valid Python).

**Issue:** The value is not required to be hexadecimal. A newline or terminal escape within the first 12 characters is printed by `--version`.

**Impact:** Whoever can set the environment for a `tiny-pki --version` run (a parent process, a unit file, CI) can break log parsers or spoof the version line. They cannot reach the CA key this way.

**Reproduction:** `TINY_PKI_GIT_SHA=$'abc\nEVIL injected line' tiny-pki --version` printed `tiny-pki 0.1.0 (abc\nEVIL inj)` as two lines.

**Recommendation:** Accept only `[0-9a-fA-F]{7,40}` and otherwise print `unknown`.

### 14. [Low] Library `validity_days` can raise `OverflowError` instead of `TinyPkiError`

**Where:** `src/tiny_pki/issue.py` `_require_validity_days` (only `> 0`) and `_validity_window`. The CLI caps `--days` at 36500 (`handlers.py` `_parse_days`).

**Issue:** `validity_days=10**12` passes the policy check and then `timedelta` / `datetime` raises `OverflowError: Python int too large to convert to C int`. That is not a `TinyPkiError`, so a caller that only catches `ValueError` will see a traceback.

**Impact:** A service that forwards untrusted `validity_days` to the library gets an unexpected exception. No key material in the message. The CLI is already bounded.

**Reproduction:** `.poc/repro.py` section `huge validity_days`.

**Recommendation:** Reject `validity_days` above a fixed cap (the CLI's 36500, or the CA cap) inside `_require_validity_days`.

### 15. [Low] CI installs floating `uv` and an unpinned `pip-audit` in a job that can file issues

**Where:** `.github/workflows/ci.yml` and `.github/workflows/cve-check.yml`: `astral-sh/setup-uv` is SHA-pinned, then `version: latest` (CVE job uses `"latest"`). `cve-check.yml` runs `uv run --with pip --with pip-audit` with no version pin, with `issues: write`, and exits 0 after filing a CVE issue.

**Issue:** The action SHA is pinned; the uv binary and pip-audit package are not. A compromised "latest" uv or pip-audit release executes inside the CVE workflow's token (it can open and close `security/cve` issues). It does not get `contents: write`. `GITLEAKS_VERSION`, if set, skips the gitleaks checksum on purpose (`.github/ci/secret-scan`); CI does not set it.

**Impact:** Supply-chain compromise of those tools can suppress or spoof CVE issues. It cannot push to `main` by itself. Dependabot auto-merge (`.github/workflows/dependabot-auto-merge.yml`) does not check out PR head; residual risk is that a green Dependabot bump, including `cryptography`, squash-merges with no human review.

**Reproduction:** not reproduced — reasoning only (workflow text).

**Recommendation:** Pin `setup-uv`'s `version` to a digest or exact uv release. Pin `pip-audit` the same way. Keep auto-merge off for the `cryptography` dependency, or require a human review for it.

### 16. [Info] Docs and defaults that are safe only if the reader already knows the caveat

**Where:** `README.md` (library snippet has no `permitted_subtrees`; line 10 says cryptography 43.0.1 or newer while `pyproject.toml` requires `>=50.0.1`). `docs/security.md` (CA key at rest, CRL freshness, PKCS#12 — these are accurate). `docs/monitoring.md` file-check recipe (`tiny-pki check /etc/nginx/certs --ca …`) has no CRL input; `check PATH` accepts `--ca` but not a CRL. `docs/api.md` states that client certificates have no SAN and that single-label CNs are not name-constrained.

**Issue:** None of these by themselves mint a bad certificate. Together they are easy to misread: an unconstrained library CA is what the first snippet creates; file-based `check` will not notice revocation; a stolen key constrained with `--permit home` can still issue client certificate `CN=alice` because that name is not a DNS name (`tests/test_ca_constraints.py` encodes this on purpose).

**Impact:** Operators and embedders who copy the snippet or the nginx check recipe get a weaker setup than the security notes describe. Client-identity spoofing with a stolen CA key is not what name constraints stop.

**Reproduction:** not reproduced — reasoning only, except the unconstrained-DNS case which is the same run as finding 2. README vs `pyproject.toml` compared by reading both.

**Recommendation:** Put `permitted_subtrees` in the library example, or one sentence on that snippet that omitting them means the CA can sign any name. Point the cryptography floor at 50.0.1. Add `--crl` to file `check`, and say in the nginx recipe that expiry and revocation are different checks.

### 17. [Info] PyPI trusted publishing is not set up, and PKCS#12 KDF rounds are the cryptography defaults

**Where:** No workflow under `.github/workflows/` requests `id-token: write` or calls a publish action. `SECURITY.md` already says trusted publishing waits on issue #11. `src/tiny_pki/bundle.py` uses `BestAvailableEncryption` or, with `legacy=True`, PBES1 3DES and HMAC-SHA1.

**Issue:** There is nothing to steal in a publish workflow yet, and also no environment, no attestation, and no approval gate to turn on later without a new workflow. Modern bundles observed via `openssl pkcs12 -info`: AES-256-CBC, PBKDF2-HMAC-SHA256, 20000 iterations on the key, MAC sha256 with 2048 iterations. Legacy bundles: 3DES and HMAC-SHA1, also 20000 / 2048. The 16-byte minimum password is enforced; the CLI has no `--password` argv flag (rejected) and uses `getpass` or `--password-file`.

**Impact:** Publishing later by copying a token into a secret would skip the trusted-publisher model. Iteration counts are acceptable for a random 16-byte password and weak for a human passphrase of that length; `--legacy` is opt-in and documented.

**Reproduction:** `openssl pkcs12 -info` on bundles from `.poc/repro.py` (section `pkcs12`). Publish gap: no matching workflow file.

**Recommendation:** When #11 lands, add a workflow that runs only on tags, uses GitHub's OIDC publisher, and gates on an environment with a required reviewer. Leave the KDF to cryptography unless you raise `kdf_rounds` on the builder; keep `--legacy` warned as it is.

## Areas reviewed with no findings

- **Signature and serials.** CA and leaves are SHA-256. Serials use `x509.random_serial_number()` (159 bits). Leaf AKI, CRL AKI, and the CA SKI matched on a library-issued CA (`AKI match leaf==CA.SKI True`).
- **Leaf and CA extensions.** CA: `BasicConstraints(ca=True, pathLen=0)` critical, `keyCertSign` and `cRLSign` critical. Leaves: `ca=False` critical, no `keyCertSign` / `crlSign`, EKU `clientAuth` or `serverAuth`. SAN on server certs is the normalized DNS/IP set. Client certs omit SAN on purpose (CN is the mTLS identity). CA `digitalSignature` and non-critical EKU are normal for this profile; not treated as a defect.
- **Names.** Control characters, bidi/format characters, `/` and `\`, URLs, `host:port`, CIDR SANs, and IDNA2003-only labels are rejected. `_dns_within` keeps a label boundary (`notexample.com` does not match `example.com`). A CN outside the DNS constraint is not, by itself, a bypass: with SANs present, TLS uses the SAN (`CN=evil.com` plus `SAN=api.home` verifies as a chain and is not a certificate for `evil.com`).
- **PKCS#12 and Fernet passwords.** No password on argv. REPL history is a mode-`0600` file under `~/.cache/tiny-pki/` (created before `FileHistory` opens it). `inspect` on `ca.key` did not echo key bytes. Fernet uses HKDF-SHA256 with a fixed `info` label; `info=None` is the documented legacy SHA-256 derivation. The 32-character floor is not an entropy check; `docs/api.md` already says repeated letters are not a strong secret.
- **Path escape.** `..`, absolute paths, and symlinks that resolve outside the store are rejected on index read and on CA/CRL/index writes. Legacy migration refuses a `certs/` key path that is not under `certs/`.
- **CI structure.** `ci.yml` `permissions: contents: read`; checkout uses `persist-credentials: false`. Third-party actions in-tree are full SHA pins. `pull_request_target` auto-merge does not checkout the PR. Branch names are expanded inside double quotes in the cleanup workflows, which does not re-run command substitution (checked). `uv.lock` pins `cryptography` 50.0.1 with sha256 hashes (208 hash entries in the lockfile).
