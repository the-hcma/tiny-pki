# tiny-pki

[![PyPI version](https://img.shields.io/pypi/v/tiny-pki.svg)](https://pypi.org/project/tiny-pki/)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/the-hcma/tiny-pki/blob/main/LICENSE)
[![CI](https://github.com/the-hcma/tiny-pki/actions/workflows/ci.yml/badge.svg)](https://github.com/the-hcma/tiny-pki/actions/workflows/ci.yml)

Small **private CA** toolkit for Python: issue CA / server / client certificates,
generate CRLs, export PKCS#12 bundles, and inspect PEMs. Built on
[`cryptography`](https://cryptography.io/).

Intended consumers:

- [my-tracks](https://github.com/the-hcma/my-tracks) — MQTT TLS client certs
- [home-warden](https://github.com/the-hcma/home-warden) — mTLS client certs / nginx `ssl_crl` ([#49](https://github.com/the-hcma/home-warden/issues/49))

## Install (development)

```bash
uv sync --group dev
uv run tiny-pki --help
```

## Quick start (CLI)

Store path is required for write operations (`--store` or `TINY_PKI_STORE`):

```bash
uv run tiny-pki --store ./stores/ca init --cn "Home CA"
uv run tiny-pki --store ./stores/ca create client alice --days 730
uv run tiny-pki --store ./stores/ca create server api.home --san api.home --san 192.168.1.10
uv run tiny-pki --store ./stores/ca export p12 alice --password 'change-me'
uv run tiny-pki --store ./stores/ca revoke alice   # regenerates stores/ca/crl.pem
uv run tiny-pki --store ./stores/ca show certs
```

Or drop into the REPL (Vim keys by default; `edit-mode emacs` to switch):

```bash
uv run tiny-pki --store ./stores/ca
```

Point nginx `ssl_client_certificate` at `stores/ca/ca.crt` and `ssl_crl` at `stores/ca/crl.pem`
for mTLS with revocation.

## Library

Bytes-in / bytes-out core (no filesystem):

```python
from tiny_pki import generate_ca_certificate, generate_client_certificate

ca_cert, ca_key = generate_ca_certificate("Home CA")
client_cert, client_key = generate_client_certificate(ca_cert, ca_key, "alice")
```

## License

MIT © 2026 Henrique Andrade ([GitHub's thehcma](https://github.com/thehcma)) — see [`LICENSE`](./LICENSE).

Code extracted from my-tracks was relicensed MIT by the copyright holder for this
shared package.
