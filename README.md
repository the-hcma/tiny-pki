# tiny-pki

[![PyPI version](https://img.shields.io/pypi/v/tiny-pki.svg)](https://pypi.org/project/tiny-pki/) [![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/) [![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/the-hcma/tiny-pki/blob/main/LICENSE) [![CI](https://github.com/the-hcma/tiny-pki/actions/workflows/ci.yml/badge.svg)](https://github.com/the-hcma/tiny-pki/actions/workflows/ci.yml)

A small **private certificate authority** for mutual TLS on home and internal networks: issue a CA and its client and server certificates, revoke them with a CRL, hand them to phones as PKCS#12 bundles, and watch for expiry. Built on [`cryptography`](https://cryptography.io/) 50.0.1 or newer.

It comes in two layers; use either:

- **Library** (`import tiny_pki`): bytes in, bytes out. No filesystem, no global state, no framework. Your application stores the PEMs.
- **CLI** (`tiny-pki`): one-shot commands and a REPL over a CA kept in a directory, for operators running nginx or Mosquitto with mTLS.

What it covers:

- CA, client and server certificates with RSA (the default) or ECDSA P-256 keys, mixed freely under one CA.
- Name Constraints, so a stolen CA key cannot impersonate public sites.
- CRLs with monotonic numbers, and a key-free `public/` directory to hand to a sandboxed TLS server.
- PKCS#12 bundles for phones and browsers, with a legacy mode for old keychains.
- `check`, an expiry and revocation monitor with Nagios-style exit codes and JSON output.
- Rotation without downtime (`create client --keep-previous`), dry runs for destructive commands, and a store that is safe under concurrent writers.
- Tab completion for bash, zsh, fish and the REPL.

Consumers: [my-tracks](https://github.com/the-hcma/my-tracks) (MQTT client certificates, library; [my-tracks#1345](https://github.com/the-hcma/my-tracks/issues/1345)) and [home-warden](https://github.com/the-hcma/home-warden) (nginx mTLS, CLI store; [home-warden#49](https://github.com/the-hcma/home-warden/issues/49)).

## Install

The library depends only on `cryptography`. The command-line tool also needs `prompt-toolkit`, which comes with the `cli` extra:

```bash
uv add tiny-pki                      # library, or: pip install tiny-pki
pipx install 'tiny-pki[cli]'         # CLI, or: uv tool install 'tiny-pki[cli]'
```

Without the extra, `tiny-pki` exits with a message saying how to install it.

## Quick start: library

Issue a CA, a client certificate, a server certificate and a CRL, all as PEM bytes:

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

# Constrain every name type (DNS and IP) your devices use; without
# permitted_subtrees the CA can sign any name, including public sites.
ca_cert, ca_key = generate_ca_certificate("Home CA", key_type="ec-p256", permitted_subtrees=["home", "192.168.0.0/16"])

client_cert, client_key = generate_client_certificate(ca_cert, ca_key, "alice", key_type="ec-p256")
server_cert, server_key = generate_server_certificate(ca_cert, ca_key, "api.home", ["api.home"])
print(get_certificate_fingerprint(client_cert))  # SHA-256, colon-separated hex

# Revoke alice: pass every revoked (serial, revoked_at) pair each time.
serial = get_certificate_serial_number(client_cert)
crl_pem = generate_crl(ca_cert, ca_key, [(serial, datetime.now(UTC))])

# A password-protected bundle for a phone or browser.
p12 = generate_pkcs12(client_cert, client_key, ca_cert, "alice", b"change-me-to-a-long-random-password")
```

Storing the results, and encrypting the CA key at rest, is up to your application; [docs/api.md](https://github.com/the-hcma/tiny-pki/blob/main/docs/api.md) has the full API and [docs/security.md](https://github.com/the-hcma/tiny-pki/blob/main/docs/security.md) the key-handling advice.

## Quick start: CLI

The CLI keeps one CA per directory, given with `--store` or `TINY_PKI_STORE`:

```bash
export TINY_PKI_STORE=./stores/home-ca
tiny-pki init --cn "Home CA" --permit home --permit 192.168.0.0/16
tiny-pki create server api.home --san api.home --san 192.168.1.10
tiny-pki create client alice
tiny-pki export p12 alice           # prompts for the bundle password
tiny-pki list clients
tiny-pki revoke alice --dry-run     # preview; writes nothing
tiny-pki revoke alice               # republishes public/crl.pem
tiny-pki check                      # exit 0 ok, 1 expiring, 2 expired/revoked/untrusted, 3 error
```

Run `tiny-pki` with no command for the REPL, and `help COMMAND` for any command's flags. Point nginx's `ssl_client_certificate` at `public/ca.crt` and `ssl_crl` at `public/crl.pem`, reload it after each revoke, and republish the CRL (`tiny-pki crl`) on a timer: it is valid for 30 days by default.

## Documentation

| Page | Contents |
| --- | --- |
| [docs/cli.md](https://github.com/the-hcma/tiny-pki/blob/main/docs/cli.md) | Every command and flag, plus rotation, nginx and CRL-timer workflows |
| [docs/api.md](https://github.com/the-hcma/tiny-pki/blob/main/docs/api.md) | Library functions, constants, errors and warnings |
| [docs/store.md](https://github.com/the-hcma/tiny-pki/blob/main/docs/store.md) | Store layout, `public/`, locking, `index.json`, and the store API |
| [docs/monitoring.md](https://github.com/the-hcma/tiny-pki/blob/main/docs/monitoring.md) | `check` output, JSON schema, exit codes, cron and systemd recipes |
| [docs/security.md](https://github.com/the-hcma/tiny-pki/blob/main/docs/security.md) | CA key handling, name constraints, choosing a key type, CRL freshness |
| [docs/defaults.md](https://github.com/the-hcma/tiny-pki/blob/main/docs/defaults.md) | Every default and the reasoning behind it |
| [CHANGELOG.md](https://github.com/the-hcma/tiny-pki/blob/main/CHANGELOG.md) | Release notes |
| [SECURITY.md](https://github.com/the-hcma/tiny-pki/blob/main/SECURITY.md) | Reporting a vulnerability |

## What stays in your app

tiny-pki deliberately does not:

- Persist anything for library callers; store the PEMs in your database or files.
- Encrypt keys at rest by itself. The optional `tiny_pki.secrets` Fernet helpers take a secret you supply; wiring and rotating it are yours (see [docs/security.md](https://github.com/the-hcma/tiny-pki/blob/main/docs/security.md)).
- Reload nginx, Mosquitto or any other TLS server after a new CRL.
- Schedule CRL renewal; run `tiny-pki crl` or `generate_crl` on a timer.
- Decide who gets a certificate; authenticating issuance requests is the application's job.

## Development

```bash
uv sync --group dev
uv run ruff check src tests && uv run ruff format --check src tests
uv run pyright
uv run pytest
uv run tiny-pki --version   # tiny-pki <version> (<commit>)
```

Contribution rules (stacked PRs, commit style, review flow) are in [AGENTS.md](https://github.com/the-hcma/tiny-pki/blob/main/AGENTS.md).

## License

MIT © 2026 Henrique Andrade ([GitHub's thehcma](https://github.com/thehcma)); see [LICENSE](https://github.com/the-hcma/tiny-pki/blob/main/LICENSE). Code extracted from my-tracks was relicensed MIT by the copyright holder for this shared package.
