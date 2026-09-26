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
