# Library API

Everything below is importable from `tiny_pki` unless noted. All certificates and
keys are **PEM `bytes`**; private keys must be **unencrypted** RSA PEM (decrypt
before calling — see [`security.md`](security.md)). Invalid input raises
`ValueError` with the expected and actual values in the message.

## Issue

| Function | Returns |
| --- | --- |
| `generate_ca_certificate(common_name="Private CA", *, organization_name="tiny-pki", validity_days=3650, key_size=4096)` | `(ca_cert_pem, ca_key_pem)` — self-signed, `BasicConstraints(ca=True)`, `keyCertSign` + `cRLSign` |
| `generate_client_certificate(ca_cert_pem, ca_key_pem, common_name, *, organization_name=None, validity_days=1825, key_size=4096)` | `(cert_pem, key_pem)` — `CLIENT_AUTH` EKU; CN is the identity |
| `generate_server_certificate(ca_cert_pem, ca_key_pem, common_name, san_entries, *, organization_name=None, validity_days=1825, key_size=4096)` | `(cert_pem, key_pem)` — `SERVER_AUTH` EKU; `san_entries` are DNS names or IP literals (at least one) |

`organization_name=None` on leaves inherits the CA's `O`. `key_size` must be one of
`ALLOWED_KEY_SIZES` (`2048`, `3072`, `4096`); `validity_days` must be positive.

## Revoke

| Function | Returns |
| --- | --- |
| `generate_crl(ca_cert_pem, ca_key_pem, revoked_entries, *, validity_days=30)` | CRL PEM signed by the CA |

`revoked_entries` is a `list[tuple[int, datetime]]` of `(serial_number,
revoked_at)`. The CRL's `nextUpdate` is `validity_days` from now — relying parties
(nginx, OpenSSL) reject an expired CRL, so regenerate on a schedule shorter than
that window. Pass the **full** revoked set every time; the CRL is not incremental.

## Bundle

| Function | Returns |
| --- | --- |
| `generate_pkcs12(cert_pem, key_pem, ca_cert_pem, friendly_name, password)` | PKCS#12 `bytes` (cert + key + CA chain) |

`password` is `bytes` and must be non-empty.

## Inspect

All take a certificate PEM.

| Function | Returns |
| --- | --- |
| `get_certificate_expiry(cert_pem)` | `datetime` (UTC, `notAfter`) |
| `get_certificate_fingerprint(cert_pem)` | SHA-256, colon-separated upper-case hex |
| `get_certificate_issuer(cert_pem)` | issuer CN (or full DN if no CN) |
| `get_certificate_metadata(cert_pem)` | `dict` of subject fields present: `CN`, `O`, `OU`, `C`, `ST`, `L` |
| `get_certificate_sans(cert_pem)` | `list[str]` of DNS + IP SANs (empty if none) |
| `get_certificate_serial_number(cert_pem)` | `int` |
| `get_certificate_subject(cert_pem)` | subject CN (or full DN if no CN) |
| `is_certificate_self_signed(cert_pem)` | `True` only if issuer == subject **and** the signature verifies with its own key |

## Constants

| Name | Value |
| --- | --- |
| `ALLOWED_KEY_SIZES` | `(2048, 3072, 4096)` |
| `DEFAULT_CA_VALIDITY_DAYS` | `3650` |
| `DEFAULT_CERT_VALIDITY_DAYS` | `1825` |
| `DEFAULT_ORGANIZATION_NAME` | `"tiny-pki"` |
| `VALIDITY_PRESETS` | `[(365, "1 year"), …, (1825, "5 years")]` for UI pickers |

## Optional: `tiny_pki.secrets`

Fernet helpers for encrypting private keys at rest. Import from the submodule:

```python
from tiny_pki.secrets import decrypt_private_key, encrypt_private_key, reencrypt_private_key
```

| Function | Returns |
| --- | --- |
| `encrypt_private_key(pem_data, secret)` | Fernet token `bytes` |
| `decrypt_private_key(encrypted_data, secret)` | PEM `bytes` (raises `cryptography.fernet.InvalidToken` on a wrong secret) |
| `reencrypt_private_key(encrypted_data, old_secret, new_secret)` | new token — use when rotating the secret |
| `derive_fernet_key(secret)` | the Fernet key (`urlsafe_b64(sha256(secret))`) |

The secret is used verbatim (no salt / KDF stretching), so it must already be
high-entropy — e.g. Django's `SECRET_KEY`, not a human password.

## Optional: `tiny_pki.store`

`CertificateStore(root)` is the filesystem store the CLI uses. Library callers
normally don't need it; it is documented in [`store.md`](store.md).
