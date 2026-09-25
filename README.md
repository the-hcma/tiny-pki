# tiny-pki

[![PyPI version](https://img.shields.io/pypi/v/tiny-pki.svg)](https://pypi.org/project/tiny-pki/)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/the-hcma/tiny-pki/blob/main/LICENSE)
[![CI](https://github.com/the-hcma/tiny-pki/actions/workflows/ci.yml/badge.svg)](https://github.com/the-hcma/tiny-pki/actions/workflows/ci.yml)

Small **private CA** toolkit for Python: issue CA / server / client certificates,
generate CRLs, export PKCS#12 bundles, and inspect PEMs. Built on
[`cryptography`](https://cryptography.io/).

Two layers, pick one:

- **Library** (`import tiny_pki`) — bytes in / bytes out. No filesystem, no
  Django, no global state. Your app owns persistence.
- **CLI** (`tiny-pki`) — a REPL / one-shot tool backed by a filesystem store,
  for operators who want a CA on disk (e.g. nginx mTLS).

Intended consumers:

- [my-tracks](https://github.com/the-hcma/my-tracks) — MQTT TLS client certs
  (library; [my-tracks#1345](https://github.com/the-hcma/my-tracks/issues/1345))
- [home-warden](https://github.com/the-hcma/home-warden) — mTLS client certs +
  nginx `ssl_crl` (CLI store; [home-warden#49](https://github.com/the-hcma/home-warden/issues/49))

## Install

```bash
uv add tiny-pki            # or: pip install tiny-pki
```

Until 0.1.0 is on PyPI ([#11](https://github.com/the-hcma/tiny-pki/issues/11)),
install from Git:

```bash
uv add git+https://github.com/the-hcma/tiny-pki
```

For development in this repo:

```bash
uv sync --group dev
uv run tiny-pki --version   # tiny-pki <version> (<commit>)
uv run tiny-pki --help
```

## Quick start (library)

Issue a CA, a client cert, a server cert, and a CRL — all as PEM bytes:

```python
from datetime import UTC, datetime

from tiny_pki import (
    generate_ca_certificate,
    generate_client_certificate,
    generate_crl,
    generate_pkcs12,
    generate_server_certificate,
    get_certificate_fingerprint,
    get_certificate_serial_number,
)

# Keys default to RSA 3072 (leaves) / 4096 (CA); 2048 keeps this example fast.
ca_cert, ca_key = generate_ca_certificate("Home CA", key_size=2048)

client_cert, client_key = generate_client_certificate(ca_cert, ca_key, "alice", key_size=2048)
server_cert, server_key = generate_server_certificate(
    ca_cert, ca_key, "api.home", ["api.home", "192.168.1.10"], key_size=2048
)

# Revoke alice: the CRL lists (serial, revoked_at) pairs, signed by the CA.
serial = get_certificate_serial_number(client_cert)
crl_pem = generate_crl(ca_cert, ca_key, [(serial, datetime.now(UTC))])

# Password-protected bundle for phones / browsers.
p12 = generate_pkcs12(client_cert, client_key, ca_cert, "alice", b"change-me")

print(get_certificate_fingerprint(client_cert))
```

Every function returns bytes (or plain values); writing them to disk, a
database, or nginx is up to you. See [`docs/api.md`](docs/api.md) for the full
API, [`docs/security.md`](docs/security.md) for CA-key handling, and
[`docs/defaults.md`](docs/defaults.md) for every default and the reason behind it.

## Quick start (CLI)

Store path is required for write operations (`--store` or `TINY_PKI_STORE`).
Inside this repo's dev checkout, prefix commands with `uv run`.

```bash
tiny-pki --store ./stores/ca init --cn "Home CA" --permit home --permit 192.168.0.0/16
tiny-pki --store ./stores/ca create client alice --days 730
tiny-pki --store ./stores/ca create server api.home --san api.home --san 192.168.1.10
tiny-pki --store ./stores/ca export p12 alice   # prompts for the bundle password (or --password-file PATH)
tiny-pki --store ./stores/ca revoke alice   # regenerates stores/ca/ca/crl.pem
tiny-pki --store ./stores/ca list clients
tiny-pki --store ./stores/ca show certs
tiny-pki --store ./stores/ca check --within 30   # exit 0 ok, 1 expiring, 2 expired/revoked/untrusted, 3 error
```

Or drop into the REPL (Vim keys by default; `edit-mode emacs` to switch):

```bash
tiny-pki --store ./stores/ca
```

Point nginx `ssl_client_certificate` at `stores/ca/ca/ca.crt` and `ssl_crl` at
`stores/ca/ca/crl.pem` for mTLS with revocation. The CRL is valid for 30 days:
re-run `tiny-pki --store ./stores/ca crl` (and reload nginx) before it expires.

Server certificates default to 90 days and client certificates to 397 days
(capped at 200 / 825; `--allow-long-validity` overrides). Re-issue with `create`
before they expire — see [`docs/defaults.md`](docs/defaults.md#lifetimes) for the rationale.

`check` lists the CA, the CRL, and every live leaf, soonest expiry first, and flags anything
expired, expiring, revoked, or not signed by the CA. The window is `--within DAYS`, `--by
YYYY-MM-DD` (end of that day, local time), or by default a third of each certificate's lifetime
(capped at 30 days for leaves and 180 for the CA). Filter with `--kind ca|client|server|crl`
(repeatable), add `--include-revoked`, print only problems with `--quiet`, or get machine-readable
output with `--json`. Exit codes follow the Nagios convention, so it drops into cron or a
monitoring agent unchanged.

`check PATH...` checks files instead of the store: PEM or DER certificates, chain files (each
certificate is checked), CRLs, PKCS#12 bundles (`--password-file PATH`), and directories
(`*.pem`, `*.crt`, `*.cer`, `*.crl`, `*.p12`, `*.pfx`, one level deep; unreadable entries are
skipped with a note). No store is needed. Add `--ca PATH` to also flag certificates and CRLs not
issued by that CA.

### Store layout

```text
$TINY_PKI_STORE/
  ca/ca.crt  ca/ca.key  ca/crl.pem  ca/index.json
  clients/{cn}-{serial}.{crt,key}
  servers/{cn}-{serial}.{crt,key}
  bundles/{cn}-{serial}.p12
```

List by category:

```bash
tiny-pki --store ./stores/ca list
tiny-pki --store ./stores/ca list clients
tiny-pki --store ./stores/ca list servers
tiny-pki --store ./stores/ca list revoked
tiny-pki --store ./stores/ca list certs --json
```

See [`docs/store.md`](docs/store.md) for the index format and legacy-layout
migration.

### Shell completion

`tiny-pki completion <bash|zsh|fish>` prints a completion script. Install it to
the per-user completion dir (idempotent; `--force` to overwrite, `--json`
reports the path):

```bash
tiny-pki completion bash --install
tiny-pki completion zsh --install    # then put its dir on $fpath before compinit
tiny-pki completion fish --install
```

Or place it yourself — bash-completion v2 lazy-loads this path (no rc edit):

```bash
tiny-pki completion bash > ~/.local/share/bash-completion/completions/tiny-pki.bash
tiny-pki completion fish > ~/.config/fish/completions/tiny-pki.fish
```

Open a new shell afterwards. The script completes top-level flags and PKI
verbs; keep `tiny-pki` on `PATH`.

## What stays in your app

tiny-pki deliberately does **not**:

- Persist anything for library callers — store PEMs in your DB / files.
- Encrypt keys at rest on its own — the optional `tiny_pki.secrets` Fernet
  helpers take the secret you pass (e.g. Django `SECRET_KEY`); wiring and
  rotation are yours.
- Reload nginx, Mosquitto, or any TLS server after a new CRL.
- Schedule CRL renewal — run `tiny-pki crl` (or call `generate_crl`) on a timer.
- Decide who gets a certificate — authn/authz for issuance is the app's job.

## License

MIT © 2026 Henrique Andrade ([GitHub's thehcma](https://github.com/thehcma)) — see [`LICENSE`](./LICENSE).

Code extracted from my-tracks was relicensed MIT by the copyright holder for this
shared package.
