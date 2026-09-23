# tiny-pki

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

MIT — see [LICENSE](./LICENSE). Code extracted from my-tracks was relicensed MIT
by the copyright holder for this shared package.
