# Defaults and why

This page lists every default tiny-pki ships with, the guidance behind it, and
how to override it. It is the output of the defaults audit
([#32](https://github.com/the-hcma/tiny-pki/issues/32)). Constants are exported
from `tiny_pki` unless noted.

## Keys and signatures

| Setting | Default | Override | Rationale |
| --- | --- | --- | --- |
| CA key size | 4096-bit RSA (`DEFAULT_CA_KEY_SIZE`) | `key_size=` / `--key-size` | The CA outlives its leaves by years. NIST SP 800-57 accepts 2048-bit RSA only through 2030, so the long-lived key gets the most headroom. |
| Leaf key size | 3072-bit RSA (`DEFAULT_LEAF_KEY_SIZE`) | `key_size=` / `--key-size` | About 128-bit security (NIST SP 800-57), acceptable past 2030, and still fast on phones. |
| Allowed key sizes | 2048, 3072, 4096 (`ALLOWED_KEY_SIZES`) | none | Smaller keys are broken or deprecated; larger ones cost a lot and add little. 2048 remains for constrained or legacy clients. |
| Public exponent | 65537 | none | The only value interoperable stacks expect (RFC 8017, NIST SP 800-56B). |
| Signature hash | SHA-256 (certificates and CRLs) | none | CA/B Forum Baseline Requirements minimum; universally supported. |
| Serial numbers | 159 random bits (`x509.random_serial_number()`) | none | Baseline Requirements require at least 64 bits of CSPRNG output; unpredictable serials block chosen-prefix collision attacks. |

ECDSA P-256 keys are tracked separately in
[#33](https://github.com/the-hcma/tiny-pki/issues/33).

## Lifetimes

| Setting | Default | Cap | Override | Rationale |
| --- | --- | --- | --- | --- |
| CA validity | 3650 days (`DEFAULT_CA_VALIDITY_DAYS`) | none | `validity_days=` / `--days` | Re-installing a root on every device is expensive, so a private root lasts about ten years. Leaves may not outlive it. |
| Server validity | 90 days (`DEFAULT_SERVER_VALIDITY_DAYS`) | 200 days (`MAX_SERVER_VALIDITY_DAYS`) | `allow_long_validity=True` / `--allow-long-validity` | Let's Encrypt issues 90-day certificates. CA/B Forum SC-081 caps public TLS at 200 days from 2026-03-15, falling to 100 (2027) and 47 (2029). |
| Client validity | 397 days (`DEFAULT_CLIENT_VALIDITY_DAYS`) | 825 days (`MAX_CLIENT_VALIDITY_DAYS`) | `allow_long_validity=True` / `--allow-long-validity` | Client certificates are re-provisioned by hand on phones, so they get about a year (the pre-SC-081 public limit). The cap matches Apple's limit. |
| Apple warning | above 825 days (`APPLE_MAX_SERVER_VALIDITY_DAYS`) | n/a | n/a | iOS and macOS reject TLS server certificates valid for more than 825 days, even from private CAs. tiny-pki emits `TinyPkiWarning` when a bypass goes past it. |
| Leaf outliving CA | rejected | n/a | none | A leaf that expires after its CA fails validation for its last stretch. `ValueError` says which `validity_days` still fits, or tells you to renew the CA. |
| Clock-skew backdate | 5 minutes (`CLOCK_SKEW_BACKDATE`) | n/a | none | `notBefore` and a CRL's `lastUpdate` are backdated so devices with slightly slow clocks accept fresh artifacts. The whole window shifts, so the encoded lifetime still equals `validity_days`. |
| CRL `nextUpdate` | 30 days | none | `validity_days=` on `generate_crl` | Relying parties reject an expired CRL, so republish well within the window. |
| Expiry warning window | one third of the lifetime | 30 days for leaves (`MAX_LEAF_WARNING_DAYS`), 180 days for the CA (`MAX_CA_WARNING_DAYS`), uncapped for CRLs | `within=` / `by=` on `check_certificate` and `check_crl` | Let's Encrypt renews at a third of the lifetime remaining. The CA gets a longer runway because replacing it means re-installing the root on every device. |

## Names

| Setting | Default | Rationale |
| --- | --- | --- |
| Subject CN / O | trimmed; control, format, private-use, and separator characters rejected; 64 characters max | RFC 5280 upper bounds. Invisible characters let two different names look identical. |
| DNS SANs | lowercased, trailing dot stripped, IDNs converted to punycode, LDH labels, wildcard only as the whole leftmost label with at least two labels after it | RFC 1035/5890/6125 and the Baseline Requirements. Matching is done on the A-label form. |
| IP SANs | canonicalized; scope IDs and CIDR ranges rejected | An IP SAN names exactly one address. |
| URL SANs | rejected | A pasted `https://…` never matches a hostname. |
| CN as SAN | a host-like CN missing from the SANs is added, with a warning (the CLI asks first, or add `--yes` / `--no-cn-san`) | Browsers ignore the CN (RFC 6125); forgetting to repeat it in the SANs is the most common private-CA mistake. |

## CA constraints and CRLs

| Setting | Default | Rationale |
| --- | --- | --- |
| `BasicConstraints` | `ca=True, path_length=0` (critical) | tiny-pki never creates intermediates, so the CA can't mint subordinate CAs. |
| Name constraints | off; `permitted_subtrees=` / `init --permit` adds critical `NameConstraints` | Limits what a stolen CA key can impersonate. tiny-pki also refuses to issue leaves outside the constraints. |
| CRL extensions | `CRLNumber` (microseconds since the epoch; the CLI store also records the last number in `ca/crlnumber` and never goes below `last + 1`) and `AuthorityKeyIdentifier` | RFC 5280 requires both. A monotonic number lets clients discard older CRLs. |

## Secrets and bundles

| Setting | Default | Override | Rationale |
| --- | --- | --- | --- |
| PKCS#12 encryption | AES-256-CBC, PBKDF2-HMAC-SHA256, HMAC-SHA256 MAC | `legacy=True` / `export p12 --legacy` (3DES, SHA-1 MAC) | Modern, widely supported format. Legacy mode is only for older Android or Apple keychains. |
| PKCS#12 password | at least 16 bytes (`MIN_PKCS12_PASSWORD_LENGTH`) | none | The bundle can be attacked offline. The CLI never takes it as an argument (visible in history and `ps`). It prompts twice, or reads `--password-file` and then offers to delete the file. |
| Fernet secret | at least 32 characters (`tiny_pki.secrets.MIN_SECRET_LENGTH`) | none | The key is HKDF-SHA256 of the secret with the `DEFAULT_INFO` label (`info=None` reads legacy `sha256(secret)` tokens), with no stretching, so the secret must already be high-entropy (Django's `SECRET_KEY` is 50). Decryption accepts shorter secrets so you can rotate off them. |
| On-disk keys (CLI store) | mode `0600` from creation | none | No window where the file is world-readable. |
