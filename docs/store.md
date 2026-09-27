# Filesystem store (CLI)

The CLI keeps one CA per store directory. Writes always need an explicit path
(`--store PATH` or `TINY_PKI_STORE`); an empty value or `.` is refused.

```text
$TINY_PKI_STORE/
  ca/
    ca.crt        # CA certificate
    ca.key        # CA private key (mode 0600, unencrypted PEM)
    crl.pem       # current CRL (rewritten on revoke / delete / crl)
    crlnumber     # last published CRL number (keeps it monotonic across clock steps)
    index.json    # source of truth for issued certificates
    .lock         # flock target that serializes writers (empty, mode 0600)
  clients/{cn}-{serial}.{crt,key}
  servers/{cn}-{serial}.{crt,key}
  bundles/{cn}-{serial}.p12
```

Private keys, PKCS#12 bundles, and `index.json` are created with mode `0600`
from the first byte. Directories the store creates are `0700`, whatever the
umask. Existing store directories you own lose their world-write bit when the
store is opened. Group write is kept, since a group-shared store is a deliberate
choice, and read access is left alone, so a TLS server that reads `ca/crl.pem`
or `ca/ca.crt` as another user keeps working. If a new store
must be readable by such a user (nginx workers do not need it; the master reads
`ssl_*` files as root), grant access to those files deliberately. Leaf and bundle
writes, and leaf reads such as `export`, refuse a symlink at any path component.
Every write goes to a temp file in the same directory, is `fsync`ed, and is
renamed into place, so a crash or a concurrent reader (an nginx reload) never
sees a truncated key, CRL, or index.
File names include the hex serial so re-issuing a CN never overwrites the old
material.

## Concurrency

Every operation that modifies the store (`init`, `create`, `revoke`, `delete`,
`crl`, `export p12` without `--out`, and the matching `CertificateStore`
methods) holds an exclusive `flock` on `ca/.lock` for the whole
read-modify-write of `index.json`, `crlnumber` and `crl.pem`. A CRL publish
reads the revoked set, picks the CRL number and writes `crl.pem` under one
lock, so a systemd timer running `crl` while an operator runs `revoke` can
never leave a newest CRL that is missing a serial `index.json` records as
revoked, and two concurrent `create` / `revoke` / `delete` runs never lose an
index update. A second writer waits for the first to finish.

Reads (`list`, `show`, `check`, `inspect`, `export pem`) take no lock; atomic
renames mean they see either the old or the new file. The one exception is the
first read of a [legacy flat layout](#legacy-flat-layout), which migrates the
store in place and so takes the lock like any other write. On platforms without
`fcntl.flock` (Windows), operations that modify the store, including that
migration, raise `TinyPkiError` instead of running unlocked.

Library callers that compose their own read-then-write sequence, such as
signing a CRL from `revoked_entries()` and `next_crl_number()` before
`write_crl()`, should hold `with store.lock():` around the whole sequence. The
lock is re-entrant within a thread.

## `index.json`

A JSON list; each entry:

| Field | Meaning |
| --- | --- |
| `common_name` | CN of the leaf |
| `kind` | `"client"` or `"server"` |
| `serial_number` | lower-case hex |
| `cert_path`, `key_path` | `clients/<file>` or `servers/<file>` (`.crt` / `.key`), relative to the store root; empty for tombstones. Anything else is refused on read |
| `not_valid_after` | ISO-8601 UTC |
| `fingerprint` | SHA-256, colon-separated hex |
| `revoked_at` | ISO-8601 UTC, or `null` while active |

Lifecycle:

- **create** — appends an entry. Re-issuing a live CN auto-revokes the previous
  serial (it stays in the CRL).
- **revoke** — sets `revoked_at` and regenerates `ca/crl.pem`.
- **delete** — only after revoke, or with `--force`, which revokes an active
  certificate first. The entry becomes a *tombstone*: files removed, paths
  cleared, serial kept so the CRL still lists it.

Commands that take an identity accept a common name or a hex serial (`0x`
optional). A value that is one certificate's serial and another certificate's
common name is refused as ambiguous; the error names an unambiguous alternative.

Paths in the index are validated to stay under the store root; a tampered index
that points elsewhere is rejected.

## `list --json`

`list clients|servers|revoked|certs --json` prints one object per entry with `cn`,
`kind`, `serial`, `fingerprint`, `expires`, `status`, `revoked_at`, absolute
`cert_path` / `key_path` (empty for tombstones), and `store`. `list --json`
prints a summary (`ca_cn`, counts, `store`); `list ca --json` prints the CA's
`cn`, `fingerprint`, `expires`, and absolute `cert_path` / `crl_path` /
`index_path`.

## Legacy flat layout

Stores created before the typed layout kept `ca.crt` / `ca.key` / `crl.pem` /
`index.json` at the root and every leaf under `certs/`. Opening such a store with
any command migrates it in place: leaves move into `clients/` or `servers/`, the
index is rewritten, and the CA files move into `ca/` last so an interrupted
migration resumes on the next run. Migration is one-way — back up the directory
first if older tooling still reads it.

## Using the store from Python

```python
from tiny_pki.store import CertificateStore

store = CertificateStore("/srv/pki/home-ca")
ca_cert, ca_key = store.read_ca()
for entry in store.list_certificates(kind="client", status="active"):
    print(entry.common_name, entry.serial_number)
```

`list_certificates(kind=None|"client"|"server", status="all"|"active"|"revoked")`
— `"revoked"` includes tombstones; `"all"` covers entries that still have files.

The store methods below mirror the CLI verbs and keep `ca/crl.pem` in step with
`index.json`, signing with the store's CA key. None of them imports
`tiny_pki.cli`.

```python
from tiny_pki.store import CertificateStore, check_store

store = CertificateStore("/srv/pki/home-ca")
store.issue_client("alice")                         # create client alice
store.issue_server("api.home", ["api.home"])        # create server api.home --san api.home
store.revoke("alice")                               # revoke alice
store.delete("alice")                               # delete alice (force=True for a live one)
store.publish_crl()                                 # crl
rows = check_store(store, within=None, include_revoked=False)  # check (store)
```

| Method | CLI | Notes |
| --- | --- | --- |
| `issue_client(cn, ...)` / `issue_server(cn, sans, ...)` | `create` | Keyword arguments match `generate_client_certificate` / `generate_server_certificate`; `TinyPkiWarning`s propagate. A live certificate with the same CN is revoked and listed in the republished CRL. |
| `revoke(identity)` | `revoke` | Same as `mark_revoked`. |
| `delete(identity, force=False)` | `delete` | Same as `delete_certificate`. |
| `publish_crl()` | `crl` | Signs the index's revoked set; returns the CRL PEM. |
| `check_store(store, *, within, by, kinds, include_revoked)` | `check` | `(name, CertificateStatus)` rows with the same statuses and reasons as `check --json`. `index.json` is authoritative: a CRL missing a serial it records as revoked is `untrusted`. |

The lower-level `add_certificate`, `mark_revoked` and `delete_certificate` also
republish `ca/crl.pem` whenever the store has a CA, so no call sequence leaves
the CRL behind the index.
