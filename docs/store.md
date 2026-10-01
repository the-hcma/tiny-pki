# Filesystem store (CLI)

The CLI keeps one CA per store directory. Writes always need an explicit path (`--store PATH` or `TINY_PKI_STORE`); an empty value or `.` is refused. The commands that work on a store are in [cli.md](cli.md).

```text
$TINY_PKI_STORE/
  ca/
    ca.crt        # CA certificate
    ca.key        # CA private key (mode 0600; plaintext PEM or versioned Fernet ciphertext)
    crl.pem       # current CRL (rewritten on revoke / delete / crl)
    crlnumber     # last published CRL number (keeps it monotonic across clock steps)
    crldays       # CRL lifetime in days for every publish (init --crl-days / crl --days; 30 if absent)
    ocspdays      # OCSP stapling response lifetime; present only while ocsp publishing is on
    ocspurl       # OCSP responder URL written into new leaves (ocsp url URL); absent until set
    chain.pem     # intermediate CA only: the certificates above it, issuer first and root last
    chain-crl.pem # intermediate CA only: their CRLs (crl --chain-crl PATH)
    index.json    # source of truth for issued certificates
    .lock         # flock target that serializes writers (empty, mode 0600)
  public/         # key-free copies for TLS servers (0755; files 0644)
    ca.crt
    crl.pem       # the CA's CRL, followed by chain-crl.pem for an intermediate CA
    ca-chain.pem  # intermediate CA only: ca.crt followed by chain.pem
    ocsp/{cn}.der # pre-signed OCSP responses for stapling (after `ocsp`)
  clients/{cn}-{serial}.{crt,key}
  servers/{cn}-{serial}.{crt,key}
  intermediates/{cn}-{serial}.crt   # intermediate CAs this CA signed (never a key); created on first use
  bundles/{cn}-{serial}.p12
```

Private keys, PKCS#12 bundles, and `index.json` are created with mode `0600` from the first byte. `ca/ca.key` is plaintext PEM by default; `init --encrypt-key` stores a versioned Fernet ciphertext with a per-key salt and Scrypt-derived key instead. Use a long, random secret: Scrypt slows offline guessing but cannot make a weak secret strong. Directories the store creates are `0700`, whatever the umask, except `public/` (below). Existing store directories you own lose their world-write bit when the store is opened. Group write is kept, since a group-shared store is a deliberate choice, and read access is left alone. Leaf and bundle writes, and leaf reads such as `export`, refuse a symlink at any path component. Every write goes to a temp file in the same directory, is `fsync`ed, and is renamed into place, so a crash or a concurrent reader (an nginx reload) never sees a truncated key, CRL, or index. File names include the hex serial so re-issuing a CN never overwrites the old material.

## `public/` for TLS servers

A relying party needs only the CA certificate and the current CRL (and, with OCSP stapling, `public/ocsp/`), but `ca/` also holds `ca.key`. The store therefore mirrors `ca.crt` and `crl.pem` into a separate, key-free `public/` directory (mode `0755`, files `0644`) on every write that changes them, by atomic rename within that directory. Every write also resets an existing `public/` you own to those modes, so a restrictive or world-writable one is corrected; a non-directory `public` is refused. `ca/ca.crt` and `ca/crl.pem` remain for compatibility.

When the store's CA is an intermediate, `public/crl.pem` is its own CRL followed by the CRLs of the CAs above it, because nginx checks the CRL of every CA in the chain once `ssl_crl` is set, and `public/ca-chain.pem` holds the CA and its chain for `ssl_client_certificate`. `ca/crl.pem` stays the store's own CRL. Import each new issuer CRL with `crl --chain-crl PATH` before the stored one expires (see [running an intermediate CA](cli.md#running-an-intermediate-ca)). A store created before `public/` existed gets it on its next write (for example `tiny-pki crl`); a legacy flat layout gets it when it is migrated.

Point TLS servers at `public/`, and grant or bind-mount the **directory**, not the individual files. A single-file bind mount keeps pointing at the old inode after the atomic rename, so the server would keep reading a stale CRL; a directory mount sees each new file.

```nginx
ssl_client_certificate /srv/pki/home-ca/public/ca.crt;
ssl_verify_client      on;
ssl_crl                /srv/pki/home-ca/public/crl.pem;
```

For nginx (or Mosquitto) running entirely as an unprivileged user in a systemd sandbox, expose only `public/`:

```ini
[Service]
User=home-warden-nginx
ProtectHome=tmpfs
BindReadOnlyPaths=/srv/pki/home-ca/public:/etc/nginx/pki
```

and use `/etc/nginx/pki/ca.crt` / `/etc/nginx/pki/crl.pem` in the config. The TLS server never sees `ca/`. Reload it after each CRL publish (nginx reads `ssl_crl` at startup and reload). Without a sandbox, give the server's user search permission on the store root only (`chmod o+x` or a shared group). The store creates every other directory `0700`, so that exposes `public/` and nothing else. The store never re-tightens a directory you widened yourself: if you previously granted access to `ca/` so a server could read `ca/crl.pem`, set it back with `chmod 700 ca` once the server reads `public/` instead.

## Concurrency

Every operation that modifies the store (`init`, `create`, `sign`, `revoke`, `delete`, `crl`, `ocsp`, `export p12` without `--out`, and the matching `CertificateStore` methods) holds an exclusive `flock` on `ca/.lock` for the whole read-modify-write of `index.json`, `crlnumber` and `crl.pem`. A CRL publish reads the revoked set, picks the CRL number and writes `crl.pem` under one lock, so a systemd timer running `crl` while an operator runs `revoke` can never leave a newest CRL that is missing a serial `index.json` records as revoked, and two concurrent `create` / `revoke` / `delete` runs never lose an index update. A second writer waits for the first to finish.

Reads (`list`, `show`, `check`, `inspect`, `export pem`) take no lock; atomic renames mean they see either the old or the new file. `respond_ocsp` is the exception among reads: it holds the lock so each OCSP answer comes from one consistent snapshot of the index. The one exception is the first read of a [legacy flat layout](#legacy-flat-layout), which migrates the store in place and so takes the lock like any other write. On platforms without `fcntl.flock` (Windows), operations that modify the store, including that migration, raise `TinyPkiError` instead of running unlocked.

Library callers that compose their own read-then-write sequence, such as signing a CRL from `revoked_entries()` and `next_crl_number()` before `write_crl()`, should hold `with store.lock():` around the whole sequence. The lock is re-entrant within a thread.

## `index.json`

A JSON list; each entry:

| Field | Meaning |
| --- | --- |
| `common_name` | CN of the leaf or intermediate CA |
| `kind` | `"client"`, `"server"`, or `"intermediate"` (an intermediate CA this CA signed) |
| `serial_number` | lower-case hex |
| `cert_path`, `key_path` | `clients/<file>`, `servers/<file>` or `intermediates/<file>` (`.crt` / `.key`) matching `kind`, relative to the store root; empty for tombstones. `key_path` is empty for a certificate issued by `sign` from a CSR, whose key stays on the device or server, and always empty for an intermediate. Anything else is refused on read |
| `not_valid_after` | ISO-8601 UTC |
| `fingerprint` | SHA-256, colon-separated hex |
| `uri_san` | the client certificate's URI SAN; omitted when it has none |
| `revoked_at` | ISO-8601 UTC, or `null` while active |

Lifecycle:

- **create** — appends an entry. Re-issuing a live CN auto-revokes the previous serial (it stays in the CRL). `create client <cn> --keep-previous` (`issue_client(..., keep_previous=True)`) leaves the previous serial live for routine rotation; `list` and `check` mark it superseded until you revoke it by serial.
- **sign** — the same as **create**, for a certificate signed from a CSR (`sign client` or `sign server`): no key file is written and `key_path` stays empty.
- **intermediate** — `init --intermediate-of` and `sign intermediate` append an `"intermediate"` entry with no key. Renewing one never revokes the previous certificate, since its leaves still chain to it; revoke that by serial once they are replaced. An intermediate's CN cannot also name a live leaf.
- **revoke** — sets `revoked_at` and regenerates `ca/crl.pem` and `public/crl.pem`.
- **delete** — only after revoke, or with `--force`, which revokes an active certificate first. The entry becomes a *tombstone*: files removed, paths cleared, serial kept so the CRL still lists it.

Commands that take an identity accept a common name or a hex serial (`0x` optional). A value that is one certificate's serial and another certificate's common name is refused as ambiguous; the error names an unambiguous alternative. While two live certificates share a common name, the name resolves to the newest one (`export`, `show`, `inspect`), but `revoke` and `delete` by name are refused; pass `0x<serial>`.

Paths in the index are validated to stay under the store root; a tampered index that points elsewhere is rejected.

## `list --json`

`list clients|servers|intermediates|revoked|certs --json` prints one object per entry with `cn`, `kind`, `serial`, `fingerprint`, `expires`, `status`, `revoked_at`, `uri_san` (`null` without one), absolute `cert_path` / `key_path` (empty for tombstones), `store`, and `superseded_by` (the newer live serial for the same CN after `--keep-previous`, else `null`). `list --json` prints a summary (`ca_cn`, the `clients` / `servers` / `intermediates` / `revoked` counts, `store`); `list ca --json` prints the CA's `cn`, `fingerprint`, `expires`, `chain` (the CNs above an intermediate CA, issuer first; empty for a root) and `chain_path` (`null` for a root), absolute `cert_path` / `crl_path` / `index_path`, `crl_days` (the stored CRL lifetime), `ocsp_days` (the stapling response lifetime, `null` while `ocsp` publishing is off), `ocsp_dir`, and `ocsp_url` (`null` until set).

## Legacy flat layout

Stores created before the typed layout kept `ca.crt` / `ca.key` / `crl.pem` / `index.json` at the root and every leaf under `certs/`. Opening such a store with any command migrates it in place: leaves move into `clients/` or `servers/`, the index is rewritten, and the CA files move into `ca/` last so an interrupted migration resumes on the next run. Migration is one-way — back up the directory first if older tooling still reads it.

## Using the store from Python

```python
from tiny_pki.store import CertificateStore

store = CertificateStore("/srv/pki/home-ca")
ca_cert, ca_key = store.read_ca()
for entry in store.list_certificates(kind="client", status="active"):
    print(entry.common_name, entry.serial_number)
```

`list_certificates(kind=None|"client"|"server"|"intermediate", status="all"|"active"|"revoked")` — `"revoked"` includes tombstones; `"all"` covers entries that still have files.

The store methods below mirror the CLI verbs and keep `ca/crl.pem` in step with `index.json`, signing with the store's CA key. None of them imports `tiny_pki.cli`.

```python
from tiny_pki.store import CertificateStore, check_store

store = CertificateStore("/srv/pki/home-ca")
store.issue_client("alice")                         # create client alice
store.issue_server("api.home", ["api.home"])        # create server api.home --san api.home
store.sign_client_csr("laptop", csr_pem)            # sign client laptop --csr laptop.csr
store.sign_server_csr("api.home", csr_pem, ["api.home"])  # sign server api.home --csr api.csr --san api.home
store.revoke("alice")                               # revoke alice
store.delete("alice")                               # delete alice (force=True for a live one)
store.publish_crl()                                 # crl
store.publish_ocsp()                                # ocsp
store.set_ocsp_url("http://ocsp.home/")             # ocsp url http://ocsp.home/
response_der = store.respond_ocsp(request_der)      # (no CLI: for your own OCSP endpoint)

root = CertificateStore("/media/usb/root")          # created with init --path-length 1
issuing = CertificateStore("/srv/pki/issuing")
issuing.init_intermediate(root, "Home Issuing")     # init --intermediate-of /media/usb/root --cn "Home Issuing"
root.sign_intermediate_csr("Bao", csr_pem)          # sign intermediate Bao --csr bao.csr
issuing.import_chain_crl(root.publish_crl())        # crl --chain-crl /media/usb/root/public/crl.pem
rows = check_store(store, within=None, include_revoked=False)  # check (store)
```

| Method | CLI | Notes |
| --- | --- | --- |
| `issue_client(cn, ...)` / `issue_server(cn, sans, ...)` | `create` | Keyword arguments match `generate_client_certificate` / `generate_server_certificate`; `TinyPkiWarning`s propagate. A live certificate with the same CN is revoked and listed in the republished CRL. |
| `sign_client_csr(cn, csr_pem, ...)` | `sign client` | Keyword arguments match `sign_client_csr` (including `uri_san`), plus `keep_previous`. The entry has no `key_path`; replacement and CRL republishing work as for `issue_client`. |
| `sign_server_csr(cn, csr_pem, sans, ...)` | `sign server` | Keyword arguments match `sign_server_csr`. The entry has no `key_path`; replacement and CRL republishing work as for `issue_server`. |
| `revoke(identity)` | `revoke` | Same as `mark_revoked`. |
| `delete(identity, force=False)` | `delete` | Same as `delete_certificate`. |
| `publish_crl(validity_days=None)` | `crl [--days N]` | Signs the index's revoked set for the stored lifetime; returns the CRL PEM. `validity_days` also updates the stored lifetime once the CRL is written. |
| `set_crl_validity_days(days)` / `crl_validity_days` | `init --crl-days`, `crl --days` | Set or read the CRL lifetime (1–365 days, default 30) that every publish uses. |
| `publish_ocsp(validity_days=None)` / `ocsp_validity_days` | `ocsp [--days N]` | Writes `public/ocsp/<cn>.der` for every server certificate on disk and returns the paths. It turns stapling on: from then on issuing, revoking or deleting a server certificate refreshes the responses of its CN, and every `publish_crl` refreshes all of them, under the same lock. `<cn>.der` belongs to the newest live certificate of that CN, or the newest one once none is live; CNs that map to the same file name get only `<cn>-<serial>.der`. `ocsp_validity_days` is `None` while it is off. |
| `disable_ocsp()` | `ocsp disable` | Removes the responses, `public/ocsp/` (unless something else was put in it) and the stored lifetime. |
| `set_ocsp_url(url)` / `ocsp_url` | `ocsp url [URL \| --clear]` | Set (or clear with `None`) the OCSP responder URL that every later leaf carries in Authority Information Access. |
| `respond_ocsp(request_der)` | none | Answers a DER OCSP request from one locked snapshot of the index (`good`, `revoked`, or `unknown` for serials the store never issued), for a responder you run yourself. Each call takes the store lock and, for an encrypted CA, decrypts the key with Scrypt, so under real traffic serve the pre-signed `public/ocsp/` files, or call `read_ca` once and answer with `generate_ocsp_response` from an index snapshot you refresh. |
| `issue_intermediate(cn, ...)` | none | Issues an intermediate CA (keyword arguments match `generate_intermediate_ca_certificate`) and records it; returns `(entry, key_pem)` and never stores the key. |
| `sign_intermediate_csr(cn, csr_pem, ...)` | `sign intermediate` | Keyword arguments match `sign_intermediate_csr`; records the certificate with no key. |
| `init_intermediate(issuer, cn, ..., key_secret=None, issuer_key_secret=None)` | `init --intermediate-of DIR` | Creates this store's CA as an intermediate of `issuer`: the issuer records it, and this store gets the key, `ca/chain.pem`, the issuer's CRLs and its own first CRL. If that setup fails after the issuer signed, the issuer revokes the new certificate and the CA files written to this store are removed, so the call can be retried. |
| `write_ca(cert, key, chain_pem=None)` | none | With `chain_pem` (issuer first, root last, each signing the one before, with `ca=True`, `keyCertSign` when Key Usage is present, and a `path_length` that allows the CAs below it), the CA is an intermediate. Its own Name Constraints must be at least as narrow as every chain certificate's, because issuance and `check` enforce only the CA's own; intermediates tiny-pki signs inherit them, so this only refuses foreign ones. Use it to install an intermediate signed elsewhere, such as from a CSR. Previously imported chain CRLs are dropped. |
| `import_chain_crl(crl_pem)` / `read_chain_crls()` | `crl --chain-crl PATH` | Stores the CRL of a CA in the chain (it must be signed by one, and may not have a lower CRL number than the one it replaces) and republishes `public/crl.pem`. |
| `read_ca_chain()` | none | The CA certificate followed by its chain, for relying parties and PKCS#12 bundles; just the CA for a root. |
| `check_store(store, *, within, by, kinds, include_revoked)` | `check` | `(name, CertificateStatus)` rows with the same statuses and reasons as `check --json`. `index.json` is authoritative: a CRL missing a serial it records as revoked is `untrusted`. For an intermediate CA it adds `issuer NAME` and `issuer crl NAME` rows for the chain (a missing chain CRL is `untrusted`), and a root's intermediates are checked as kind `ca`. |

The lower-level `add_certificate`, `mark_revoked` and `delete_certificate` also republish `ca/crl.pem` whenever the store has a CA, so no call sequence leaves the CRL behind the index. They validate the CA signing key before updating the index; on encrypted stores they therefore need `key_secret=`, while plaintext stores need no secret.

For an encrypted CA key, pass `key_secret=` to `read_ca`, `write_ca`, `add_certificate`, `issue_client`, `issue_server`, `sign_client_csr`, `sign_server_csr`, `issue_intermediate`, `sign_intermediate_csr`, `init_intermediate` (plus `issuer_key_secret=` for the issuer's key), `publish_crl`, `publish_ocsp`, `respond_ocsp`, `mark_revoked`, `revoke`, `delete_certificate`, and `delete` as applicable. These methods continue to work without a secret for plaintext stores. `read_ca_certificate()` reads only the public certificate and remains usable without a secret; `check_store()` also needs no key secret.

`encrypt_ca_key(secret)` and `decrypt_ca_key(secret)` migrate `ca/ca.key` in place under the store lock. Ciphertext records the Scrypt work parameters alongside a random per-key salt before the Fernet token. Both use atomic mode-0600 replacement; a wrong decryption secret leaves the original ciphertext untouched.
