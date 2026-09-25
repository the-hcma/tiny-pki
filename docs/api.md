# Library API

Everything below is importable from `tiny_pki` unless noted. All certificates and
keys are **PEM `bytes`**; private keys must be **unencrypted** RSA PEM (decrypt
before calling — see [`security.md`](security.md)). Invalid input raises
`TinyPkiError` (a `ValueError`) with the expected and actual values in the message;
see [Errors and warnings](#errors-and-warnings).

The library needs only `cryptography` (`pip install tiny-pki`); none of the modules below import the CLI's `prompt-toolkit`, which is installed only with the `tiny-pki[cli]` extra.

## Issue

| Function | Returns |
| --- | --- |
| `generate_ca_certificate(common_name="Private CA", *, organization_name="tiny-pki", validity_days=3650, key_size=4096, permitted_subtrees=None)` | `(ca_cert_pem, ca_key_pem)` — self-signed, `BasicConstraints(ca=True, path_length=0)` (signs leaves only), `keyCertSign` + `cRLSign`; optional critical Name Constraints |
| `generate_client_certificate(ca_cert_pem, ca_key_pem, common_name, *, organization_name=None, validity_days=397, key_size=3072, allow_long_validity=False)` | `(cert_pem, key_pem)` — `CLIENT_AUTH` EKU; CN is the identity |
| `generate_server_certificate(ca_cert_pem, ca_key_pem, common_name, san_entries, *, organization_name=None, validity_days=90, key_size=3072, allow_long_validity=False, include_common_name_in_sans=True)` | `(cert_pem, key_pem)` — `SERVER_AUTH` EKU; `san_entries` are DNS names or IP literals (at least one) |

`organization_name=None` on leaves inherits the CA's `O`. `key_size` must be one of
`ALLOWED_KEY_SIZES` (`2048`, `3072`, `4096`); `validity_days` must be positive.

Every default and its rationale is listed in [`defaults.md`](defaults.md).

Lifetime policy:

- Leaves are capped at `MAX_SERVER_VALIDITY_DAYS` (200) / `MAX_CLIENT_VALIDITY_DAYS`
  (825). Pass `allow_long_validity=True` to exceed the cap; a server certificate
  over `APPLE_MAX_SERVER_VALIDITY_DAYS` (825) also emits a `TinyPkiWarning`
  because Apple platforms reject it.
- A leaf may not outlive its CA: issuance raises `TinyPkiError` naming the maximum
  `validity_days` still possible.
- The validity window (and a CRL's `lastUpdate`) is backdated by
  `CLOCK_SKEW_BACKDATE` (5 minutes) so devices with slightly slow clocks accept
  fresh certificates. The encoded period (`notAfter - notBefore`) is exactly
  `validity_days`, so the caps and Apple's limit apply to what is actually issued.

Name Constraints (`permitted_subtrees`, CLI `init --permit`):

- Entries are DNS suffixes (`"home"` permits `home` and every name under it) or
  IP networks (`"192.168.0.0/16"`; a bare IP is a single host). Wildcards, URLs,
  and networks with host bits set are rejected.
- Leaf issuance refuses SANs outside the constraints, so you get an error at
  issue time rather than a failed handshake later. When the leaf has no DNS SAN,
  a dotted CN made of letters, digits, `-`, `_` and `.` (IP literals included) is
  checked against the DNS constraints too, as OpenSSL does.
- RFC 5280 only constrains the name types you list: a DNS-only constraint
  leaves IP SANs unrestricted, so add your LAN ranges too.

Name rules (`tiny_pki.names`):

- CN and O are stripped; empty values, more than 64 characters (the X.509
  upper bound), and control / format characters (including zero-width) are
  rejected. Other Unicode is allowed.
- SAN entries are normalized to what TLS clients compare: lower-case DNS names
  without a trailing dot, IDNs as punycode A-labels, canonical IP literals, and
  duplicates dropped. URLs, `host:port`, CIDR ranges, IPv6 zone IDs, underscores,
  empty or over-long labels, and numeric last labels (malformed IPs) raise
  `TinyPkiError`, as do IDN labels that IDNA2003 would silently remap (`faß` →
  `fass`); pass their `xn--` form instead. Wildcards must be the whole leftmost label followed by at least
  two labels (`*.lan.example`); OpenSSL won't match shorter patterns.
- TLS clients ignore the CN, so a server CN that is itself a valid host/IP and
  missing from `san_entries` is appended with a `TinyPkiWarning`. Pass
  `include_common_name_in_sans=False` to opt out. The CLI asks first on a TTY;
  `--yes` accepts and `--no-cn-san` declines; both apply to servers only, and
  `--no-cn-san` needs `--san` (otherwise the CN is the only SAN).
- The store matches identities case-insensitively, but certificates keep the CN
  exactly as given (after stripping).
- Client certificates carry no SAN: nginx (`$ssl_client_s_dn`) and Mosquitto
  (`use_identity_as_username`) identify clients by CN.

| Function (`tiny_pki.names`) | Returns |
| --- | --- |
| `normalize_san_entries(entries)` | normalized, de-duplicated `list[str]` |
| `normalize_san_entry(entry)` / `normalize_dns_name(name)` | one normalized entry |
| `normalize_subject_attribute(value, field_name, *, max_length)` | stripped, validated CN/O |
| `common_name_as_san(common_name)` | the SAN form of a host-like CN, else `None` |

## Revoke

| Function | Returns |
| --- | --- |
| `generate_crl(ca_cert_pem, ca_key_pem, revoked_entries, *, validity_days=30, crl_number=None)` | CRL PEM signed by the CA, with `CRLNumber` and `AuthorityKeyIdentifier` (RFC 5280) |

`crl_number` defaults to microseconds since the epoch, which only increases if
the signing host's clock never goes backwards. Pass a persisted counter if you
can't guarantee that.

`revoked_entries` is a `list[tuple[int, datetime]]` of `(serial_number,
revoked_at)`. The CRL's `nextUpdate` is `validity_days` from now — relying parties
(nginx, OpenSSL) reject an expired CRL, so regenerate on a schedule shorter than
that window. Pass the **full** revoked set every time; the CRL is not incremental.

## Bundle

| Function | Returns |
| --- | --- |
| `generate_pkcs12(cert_pem, key_pem, ca_cert_pem, friendly_name, password, *, legacy=False)` | PKCS#12 `bytes` (cert + key + CA chain) |

- `password` is `bytes` of at least `MIN_PKCS12_PASSWORD_LENGTH` (8).
- By default the bundle uses AES-256-CBC with PBKDF2-HMAC-SHA256 and an
  HMAC-SHA256 MAC (`cryptography`'s best available encryption).
- `legacy=True` (CLI `export p12 --legacy`) switches to 3DES with a SHA-1 MAC,
  for older Android or Apple keychains that can't import the modern format. Use
  it only when a device needs it.
- The CLI never takes the password as an argument, because arguments end up in
  shell/REPL history and process listings. It prompts twice (the entries must match)
  or reads the first line of `--password-file PATH`. After exporting from a file, it
  warns that the file holds the password in plaintext and, on a terminal, offers to
  delete it. Otherwise it leaves the file in place and says so.

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

## Check

Expiry and validity checks for alerting (`tiny_pki.check`, re-exported from `tiny_pki`).

| Function | Returns |
| --- | --- |
| `check_certificate(cert_pem, *, now=None, within=None, by=None, ca_cert_pem=None, crl_pem=None)` | `CertificateStatus` |
| `check_crl(crl_pem, *, now=None, within=None, by=None, ca_cert_pem=None)` | `CertificateStatus` for the CRL's `nextUpdate` |
| `default_warning_window(kind, lifetime)` | `timedelta`: one third of `lifetime`, capped at `MAX_CA_WARNING_DAYS` (180) for a CA and `MAX_LEAF_WARNING_DAYS` (30) for leaves; CRLs are not capped |
| `worst_status(results)` | the most severe `Status` (`OK` for an empty list) |

- The **cutoff** is `now + within`, `by`, or the earlier of the two. With neither, it is `now + default_warning_window(kind, lifetime)`, where `lifetime` is the certificate's own `notAfter - notBefore`.
- `Status` is a `StrEnum`, declared from least to most severe: `ok`, `expiring` (valid now, gone by the cutoff), `not_yet_valid`, `expired`, `revoked`, `untrusted`. `Status.severity` gives the position.
- `CertificateStatus` fields: `kind` (`ca` / `client` / `server` / `crl` / `unknown`, from `BasicConstraints` and the EKU), `subject`, `issuer`, `serial_number` (the CRL number for CRLs), `not_before`, `not_after`, `cutoff`, `days_remaining` (whole days until `not_after`, negative once expired), `status`, and `reasons` (human-readable explanations, including informational notes such as "CA expires first").
- With `ca_cert_pem`, a certificate not signed by that CA is `untrusted`, and a CA that expires first becomes the effective `not_after`. With `crl_pem` (which requires `ca_cert_pem`), a listed serial is `revoked`. A CRL not signed by the given CA raises `TinyPkiError` from `check_certificate` and is `untrusted` from `check_crl`.
- `now` and `by` must be timezone-aware; `within` must not be negative.
- The `tiny-pki check` CLI wraps these for the store or for files; see [monitoring.md](monitoring.md) for its exit codes, JSON output, and scheduling recipes.

## Constants

| Name | Value |
| --- | --- |
| `ALLOWED_KEY_SIZES` | `(2048, 3072, 4096)` |
| `APPLE_MAX_SERVER_VALIDITY_DAYS` | `825` |
| `CLOCK_SKEW_BACKDATE` | `timedelta(minutes=5)` |
| `DEFAULT_CA_KEY_SIZE` | `4096` |
| `DEFAULT_CA_VALIDITY_DAYS` | `3650` |
| `DEFAULT_CLIENT_VALIDITY_DAYS` | `397` |
| `DEFAULT_LEAF_KEY_SIZE` | `3072` |
| `DEFAULT_ORGANIZATION_NAME` | `"tiny-pki"` |
| `DEFAULT_SERVER_VALIDITY_DAYS` | `90` |
| `MAX_CA_WARNING_DAYS` | `180` |
| `MAX_CLIENT_VALIDITY_DAYS` | `825` |
| `MAX_LEAF_WARNING_DAYS` | `30` |
| `MAX_SERVER_VALIDITY_DAYS` | `200` |
| `MIN_PKCS12_PASSWORD_LENGTH` | `8` |
| `VALIDITY_PRESETS` | `[(90, "90 days"), …, (825, "825 days")]` for UI pickers |

## Errors and warnings

`TinyPkiError` (a subclass of `ValueError`, so `except ValueError` keeps working) is raised for every input or policy rejection in `issue`, `revoke`, `bundle`, `names`, `check`, and `secrets`: a bad key size, name, or SAN, a leaf that would outlive its CA, a name-constraint violation, a short PKCS#12 password or Fernet secret, a key that is not an unencrypted RSA key, a naive datetime, and so on. Its message says what was expected and what was received and never contains key material, so it is safe to show to end users.

Other `ValueError`s still come from `cryptography` itself, for example PEM or DER input that cannot be parsed at all or a wrong password when loading a PKCS#12 bundle; `tiny_pki.store` also raises plain `ValueError`, `KeyError`, and `FileNotFoundError` for store operations.

`TinyPkiWarning` (a `UserWarning`) flags certificates that were issued but that some relying parties may reject.

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
`encrypt_private_key` and `derive_fernet_key` raise `TinyPkiError` for secrets
shorter than `MIN_SECRET_LENGTH` (32 characters). The length check is a floor,
not a strength test: 32 random characters are fine, 32 repeated letters are not.
`decrypt_private_key` accepts any non-empty secret, so
`reencrypt_private_key(token, old_weak, new_strong)` can move keys stored under
an older, shorter secret.

## Optional: `tiny_pki.store`

`CertificateStore(root)` is the filesystem store the CLI uses. Library callers
normally don't need it; it is documented in [`store.md`](store.md).
