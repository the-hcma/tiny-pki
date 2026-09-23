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

## Status

Public scaffolding. Core crypto + REPL CLI are landing next.

## Install (development)

```bash
uv sync --group dev
uv run tiny-pki --help
```

## License

MIT © 2026 Henrique Andrade ([GitHub's thehcma](https://github.com/thehcma)) — see [`LICENSE`](./LICENSE).

Code extracted from my-tracks was relicensed MIT by the copyright holder for this
shared package.
