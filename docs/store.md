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
    index.json    # source of truth for issued certificates
    .lock         # flock target that serializes writers (empty, mode 0600)
  public/         # key-free copies for TLS servers (0755; files 0644)
    ca.crt
    crl.pem
  clients/{cn}-{serial}.{crt,key}
  servers/{cn}-{serial}.{crt,key}
  bundles/{cn}-{serial}.p12
```

Private keys, PKCS#12 bundles, and `index.json` are created with mode `0600` from the first byte. `ca/ca.key` is plaintext PEM by default; `init --encrypt-key` stores a versioned Fernet ciphertext with a per-key salt and Scrypt-derived key instead. Use a long, random secret: Scrypt slows offline guessing but cannot make a weak secret strong. Directories the store creates are `0700`, whatever the umask, except `public/` (below). Existing store directories you own lose their world-write bit when the store is opened. Group write is kept, since a group-shared store is a deliberate choice, and read access is left alone. Leaf and bundle writes, and leaf reads such as `export`, refuse a symlink at any path component. Every write goes to a temp file in the same directory, is `fsync`ed, and is renamed into place, so a crash or a concurrent reader (an nginx reload) never sees a truncated key, CRL, or index. File names include the hex serial so re-issuing a CN never overwrites the old material.

## `public/` for TLS servers

A relying party needs only the CA certificate and the current CRL, but `ca/` also holds `ca.key`. The store therefore mirrors `ca.crt` and `crl.pem` into a separate, key-free `public/` directory (mode `0755`, files `0644`) on every write that changes them, by atomic rename within that directory. Every write also resets an existing `public/` you own to those modes, so a restrictive or world-writable one is corrected; a non-directory `public` is refused. `ca/ca.crt` and `ca/crl.pem` remain for compatibility. A store created before `public/` existed gets it on its next write (for example `tiny-pki crl`); a legacy flat layout gets it when it is migrated.

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

Every operation that modifies the store (`init`, `create`, `revoke`, `delete`, `crl`, `export p12` without `--out`, and the matching `CertificateStore` methods) holds an exclusive `flock` on `ca/.lock` for the whole read-modify-write of `index.json`, `crlnumber` and `crl.pem`. A CRL publish reads the revoked set, picks the CRL number and writes `crl.pem` under one lock, so a systemd timer running `crl` while an operator runs `revoke` can never leave a newest CRL that is missing a serial `index.json` records as revoked, and two concurrent `create` / `revoke` / `delete` runs never lose an index update. A second writer waits for the first to finish.

Reads (`list`, `show`, `check`, `inspect`, `export pem`) take no lock; atomic renames mean they see either the old or the new file. The one exception is the first read of a [legacy flat layout](#legacy-flat-layout), which migrates the store in place and so takes the lock like any other write. On platforms without `fcntl.flock` (Windows), operations that modify the store, including that migration, raise `TinyPkiError` instead of running unlocked.

Library callers that compose their own read-then-write sequence, such as signing a CRL from `revoked_entries()` and `next_crl_number()` before `write_crl()`, should hold `with store.lock():` around the whole sequence. The lock is re-entrant within a thread.

## `index.json`

A JSON list; each entry:

| Field | Meaning |
| --- | --- |
| `common_name` | CN of the leaf |
| `kind` | `"client"` or `"server"` |
| `serial_number` | lower-case hex |
| `cert_path`, `key_path` | `clients/<file>` or `servers/<file>` (`.crt` / `.key`), relative to the store root; empty for tombstones, and `key_path` is empty for a certificate issued by `sign` from a CSR, whose key stays on the device or server. Anything else is refused on read |
| `not_valid_after` | ISO-8601 UTC |
| `fingerprint` | SHA-256, colon-separated hex |
| `revoked_at` | ISO-8601 UTC, or `null` while active |

Lifecycle:

- **create** — appends an entry. Re-issuing a live CN auto-revokes the previous serial (it stays in the CRL). `create client <cn> --keep-previous` (`issue_client(..., keep_previous=True)`) leaves the previous serial live for routine rotation; `list` and `check` mark it superseded until you revoke it by serial.
- **sign** — the same as **create**, for a certificate signed from a CSR (`sign client` or `sign server`): no key file is written and `key_path` stays empty.
- **revoke** — sets `revoked_at` and regenerates `ca/crl.pem` and `public/crl.pem`.
- **delete** — only after revoke, or with `--force`, which revokes an active certificate first. The entry becomes a *tombstone*: files removed, paths cleared, serial kept so the CRL still lists it.

Commands that take an identity accept a common name or a hex serial (`0x` optional). A value that is one certificate's serial and another certificate's common name is refused as ambiguous; the error names an unambiguous alternative. While two live certificates share a common name, the name resolves to the newest one (`export`, `show`, `inspect`), but `revoke` and `delete` by name are refused; pass `0x<serial>`.

Paths in the index are validated to stay under the store root; a tampered index that points elsewhere is rejected.

## `list --json`

`list clients|servers|revoked|certs --json` prints one object per entry with `cn`, `kind`, `serial`, `fingerprint`, `expires`, `status`, `revoked_at`, absolute `cert_path` / `key_path` (empty for tombstones), `store`, and `superseded_by` (the newer live serial for the same CN after `--keep-previous`, else `null`). `list --json` prints a summary (`ca_cn`, counts, `store`); `list ca --json` prints the CA's `cn`, `fingerprint`, `expires`, absolute `cert_path` / `crl_path` / `index_path`, and `crl_days` (the stored CRL lifetime).

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

`list_certificates(kind=None|"client"|"server", status="all"|"active"|"revoked")` — `"revoked"` includes tombstones; `"all"` covers entries that still have files.

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
rows = check_store(store, within=None, include_revoked=False)  # check (store)
```

| Method | CLI | Notes |
| --- | --- | --- |
| `issue_client(cn, ...)` / `issue_server(cn, sans, ...)` | `create` | Keyword arguments match `generate_client_certificate` / `generate_server_certificate`; `TinyPkiWarning`s propagate. A live certificate with the same CN is revoked and listed in the republished CRL. |
| `sign_client_csr(cn, csr_pem, ...)` | `sign client` | Keyword arguments match `sign_client_csr`, plus `keep_previous`. The entry has no `key_path`; replacement and CRL republishing work as for `issue_client`. |
| `sign_server_csr(cn, csr_pem, sans, ...)` | `sign server` | Keyword arguments match `sign_server_csr`. The entry has no `key_path`; replacement and CRL republishing work as for `issue_server`. |
| `revoke(identity)` | `revoke` | Same as `mark_revoked`. |
| `delete(identity, force=False)` | `delete` | Same as `delete_certificate`. |
| `publish_crl(validity_days=None)` | `crl [--days N]` | Signs the index's revoked set for the stored lifetime; returns the CRL PEM. `validity_days` also updates the stored lifetime once the CRL is written. |
| `set_crl_validity_days(days)` / `crl_validity_days` | `init --crl-days`, `crl --days` | Set or read the CRL lifetime (1–365 days, default 30) that every publish uses. |
| `check_store(store, *, within, by, kinds, include_revoked)` | `check` | `(name, CertificateStatus)` rows with the same statuses and reasons as `check --json`. `index.json` is authoritative: a CRL missing a serial it records as revoked is `untrusted`. |

The lower-level `add_certificate`, `mark_revoked` and `delete_certificate` also republish `ca/crl.pem` whenever the store has a CA, so no call sequence leaves the CRL behind the index. They validate the CA signing key before updating the index; on encrypted stores they therefore need `key_secret=`, while plaintext stores need no secret.

For an encrypted CA key, pass `key_secret=` to `read_ca`, `write_ca`, `add_certificate`, `issue_client`, `issue_server`, `sign_client_csr`, `sign_server_csr`, `publish_crl`, `mark_revoked`, `revoke`, `delete_certificate`, and `delete` as applicable. These methods continue to work without a secret for plaintext stores. `read_ca_certificate()` reads only the public certificate and remains usable without a secret; `check_store()` also needs no key secret.

`encrypt_ca_key(secret)` and `decrypt_ca_key(secret)` migrate `ca/ca.key` in place under the store lock. Ciphertext records the Scrypt work parameters alongside a random per-key salt before the Fernet token. Both use atomic mode-0600 replacement; a wrong decryption secret leaves the original ciphertext untouched.
