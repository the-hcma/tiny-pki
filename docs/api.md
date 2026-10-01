# Library API

Everything below is importable from `tiny_pki` unless noted. All certificates and keys are **PEM `bytes`**; private keys must be **unencrypted** RSA or ECDSA P-256 PEM (decrypt before calling — see [`security.md`](security.md)). Invalid input raises `TinyPkiError` (a `ValueError`) with the expected and actual values in the message; see [Errors and warnings](#errors-and-warnings).

The library needs only `cryptography` (`pip install tiny-pki`); none of the modules below import the CLI's `prompt-toolkit`, which is installed only with the `tiny-pki[cli]` extra. The command-line tool is documented in [cli.md](cli.md).

## Issue

| Function | Returns |
| --- | --- |
| `generate_ca_certificate(common_name="Private CA", *, organization_name="tiny-pki", validity_days=3650, key_size=None, key_type="rsa", permitted_subtrees=None, path_length=0)` | `(ca_cert_pem, ca_key_pem)` — self-signed, `BasicConstraints(ca=True, path_length=path_length)`, `keyCertSign` + `cRLSign`; optional critical Name Constraints. `path_length=0` signs leaves only; `1` also signs intermediate CAs (see [Intermediate CAs](#intermediate-cas)) |
| `generate_intermediate_ca_certificate(issuer_cert_pem, issuer_key_pem, common_name, *, organization_name=None, validity_days=1825, key_size=None, key_type="rsa", permitted_subtrees=None)` | `(cert_pem, key_pem)` — an intermediate CA signed by a `path_length=1` root: `BasicConstraints(ca=True, path_length=0)`, `keyCertSign` + `cRLSign`, the issuer's Name Constraints (narrowed by `permitted_subtrees`) |
| `sign_intermediate_csr(issuer_cert_pem, issuer_key_pem, csr_pem, common_name, *, organization_name=None, validity_days=1825, permitted_subtrees=None)` | `cert_pem` — the same intermediate profile, for the public key in a CSR from a CA whose key lives elsewhere (OpenBao, another host) |
| `generate_client_certificate(ca_cert_pem, ca_key_pem, common_name, *, organization_name=None, validity_days=397, key_size=None, key_type="rsa", allow_long_validity=False, allow_dn_special_chars=False, ocsp_url=None, uri_san=None)` | `(cert_pem, key_pem)` — `CLIENT_AUTH` EKU; CN is the identity, plus an optional URI SAN |
| `generate_server_certificate(ca_cert_pem, ca_key_pem, common_name, san_entries, *, organization_name=None, validity_days=90, key_size=None, key_type="rsa", allow_long_validity=False, include_common_name_in_sans=True, allow_dn_special_chars=False, ocsp_url=None)` | `(cert_pem, key_pem)` — `SERVER_AUTH` EKU; `san_entries` are DNS names or IP literals (at least one) |
| `sign_client_csr(ca_cert_pem, ca_key_pem, csr_pem, common_name, *, organization_name=None, validity_days=397, allow_long_validity=False, allow_dn_special_chars=False, ocsp_url=None, uri_san=None)` | `cert_pem` — the same client profile as `generate_client_certificate`, for the public key in a device's CSR; see [Signing a CSR](#signing-a-csr) |
| `sign_server_csr(ca_cert_pem, ca_key_pem, csr_pem, common_name, san_entries, *, organization_name=None, validity_days=90, allow_long_validity=False, include_common_name_in_sans=True, include_csr_sans=False, allow_dn_special_chars=False, ocsp_url=None)` | `cert_pem` — the same server profile as `generate_server_certificate`, for the public key in a server's CSR; see [Signing a CSR](#signing-a-csr) |
| `max_leaf_validity_days(ca_cert_pem, *, kind="server", allow_long_validity=False)` | `int` — the largest `validity_days` issuing a `kind` leaf under this CA accepts right now (CA `notAfter` with the `CLOCK_SKEW_BACKDATE` backdate, and the per-kind cap unless `allow_long_validity`); `0` once the CA cannot sign any leaf. Use it to clamp or grey out `VALIDITY_PRESETS` in UIs |

`organization_name=None` on leaves inherits the CA's `O`. `ocsp_url` (an `http://` or `https://` URL) adds an Authority Information Access extension naming that OCSP responder; see [OCSP](#ocsp). `validity_days` must be between 1 and `MAX_VALIDITY_DAYS` (36500).

Key types (`KEY_TYPES`):

- `key_type="rsa"` (the default, `DEFAULT_KEY_TYPE`): `key_size` is one of `ALLOWED_KEY_SIZES` (`2048`, `3072`, `4096`); omitted, it is `DEFAULT_CA_KEY_SIZE` (4096) for the CA and `DEFAULT_LEAF_KEY_SIZE` (3072) for leaves.
- `key_type="ec-p256"`: ECDSA on NIST P-256. Leave `key_size` out; passing one raises `TinyPkiError`. ECDSA leaves carry `digitalSignature` without `keyEncipherment` in Key Usage (RFC 8813); RSA leaves keep both.
- The CA and its leaves may use different key types (an RSA CA can sign EC leaves and the other way round). Certificates and CRLs are signed with SHA-256 either way.
- Every function that takes `ca_key_pem` refuses a key that does not match `ca_cert_pem`. See [security.md](security.md#key-types-sizes-and-validity) for choosing between them.

Every default and its rationale is listed in [`defaults.md`](defaults.md).

Lifetime policy:

- Leaves are capped at `MAX_SERVER_VALIDITY_DAYS` (200) / `MAX_CLIENT_VALIDITY_DAYS` (825). Pass `allow_long_validity=True` to exceed the cap; a server certificate over `APPLE_MAX_SERVER_VALIDITY_DAYS` (825) also emits a `TinyPkiWarning` because Apple platforms reject it.
- A leaf may not outlive its CA: issuance raises `TinyPkiError` naming the maximum `validity_days` still possible.
- The validity window (and a CRL's `lastUpdate`) is backdated by `CLOCK_SKEW_BACKDATE` (5 minutes) so devices with slightly slow clocks accept fresh certificates. The encoded period (`notAfter - notBefore`) is exactly `validity_days`, so the caps and Apple's limit apply to what is actually issued.

Name Constraints (`permitted_subtrees`, CLI `init --permit`):

- Entries are DNS suffixes (`"home"` permits `home` and every name under it), IP networks (`"192.168.0.0/16"`; a bare IP is a single host), or URI hosts prefixed with `uri:` (`URI_SUBTREE_PREFIX`; CLI `--permit-uri`): `"uri:example.home"` permits URIs whose host is exactly `example.home`, and `"uri:.example.home"` any host under it, as RFC 5280 defines for URIs. Wildcards, URLs, networks with host bits set, and a leading dot (OpenSSL's "subdomains only" syntax, which tiny-pki does not support) are rejected.
- An excluded IPv4 network also excludes the IPv4-mapped IPv6 form (`::ffff:10.1.2.3`). A permitted IPv4 network does not admit the mapped form, since relying parties compare within one address family.
- Leaf issuance refuses SANs outside the constraints, so you get an error at issue time rather than a failed handshake later. When the leaf has no DNS SAN, a dotted CN made of letters, digits, `-`, `_` and `.` (IP literals included) is checked against the DNS constraints too, as OpenSSL does.
- RFC 5280 only constrains the name types you list: to a relying party, a DNS-only constraint leaves IP SANs unrestricted and an IP-only constraint leaves DNS names unrestricted. tiny-pki is stricter at issue time: once a CA has permitted subtrees, it refuses a DNS SAN (or a dotted, non-IP CN with no DNS SAN) unless a DNS subtree is permitted, an IP SAN unless an IP subtree is permitted, and a URI SAN unless a URI subtree is permitted. A server CN of an unlisted type is not auto-added to the SANs (a `TinyPkiWarning` says so). List every name type your devices use.

Name rules (`tiny_pki.names`):

- CN and O are stripped; empty values, more than 64 characters (the X.509 upper bound), and control / format characters (including zero-width) are rejected. Other Unicode is allowed.
- SAN entries are normalized to what TLS clients compare: lower-case DNS names without a trailing dot, IDNs as punycode A-labels, canonical IP literals, and duplicates dropped. URLs, `host:port`, CIDR ranges, IPv6 zone IDs, underscores, empty or over-long labels, and numeric last labels (malformed IPs) raise `TinyPkiError`, as do IDN labels that IDNA2003 would silently remap (`faß` → `fass`); pass their `xn--` form instead. Wildcards must be the whole leftmost label followed by at least two labels (`*.lan.example`); OpenSSL won't match shorter patterns.
- TLS clients ignore the CN, so a server CN that is itself a valid host/IP and missing from `san_entries` is appended with a `TinyPkiWarning`. Pass `include_common_name_in_sans=False` to opt out. The CLI asks first on a TTY; `--yes` accepts and `--no-cn-san` declines; both apply to servers only, and `--no-cn-san` needs `--san` (otherwise the CN is the only SAN).
- The store matches identities case-insensitively, but certificates keep the CN exactly as given (after stripping).
- Client certificates carry no SAN by default: nginx (`$ssl_client_s_dn`) and Mosquitto (`use_identity_as_username`) identify clients by CN. `uri_san` adds exactly one URI SAN for brokers that identify clients by URI (SPIFFE IDs, amqtt's `UserAuthCertPlugin`, which expects `spiffe://<uri_domain>/device/<client_id>`). `normalize_uri_san` accepts an absolute URI with a scheme and host and no user info, query, fragment, whitespace or non-ASCII characters; a `spiffe://` URI also needs a lower-case trust domain without a port and path segments of letters, digits, `.`, `-` and `_`. It lower-cases the scheme and leaves the rest unchanged. `sign_client_csr` still ignores every SAN the CSR requests.
- Client and server CNs may not contain the RFC 4514 special characters `,` `+` `=` `"` `<` `>` `;` or start with `#`. In an escaped DN string such as nginx's `$ssl_client_s_dn`, the CN `bob,CN=alice` appears as `O=tiny-pki,CN=bob\,CN=alice`, which ends in `,CN=alice`. Pass `allow_dn_special_chars=True` (CLI: `--allow-dn-special-chars`) if a deployment really needs them.
- Match an nginx CN allowlist against the whole DN string, not a suffix:

  ```nginx
  map $ssl_client_s_dn $mtls_client {
      default                 "";
      "O=tiny-pki,CN=alice"   alice;
      "O=tiny-pki,CN=bob"     bob;
  }
  ```

  A regex such as `~,CN=alice$` also matches `CN=bob\,CN=alice` if a CA ever issued one with the opt-out.

| Function (`tiny_pki.names`) | Returns |
| --- | --- |
| `normalize_san_entries(entries)` | normalized, de-duplicated `list[str]` |
| `normalize_san_entry(entry)` / `normalize_dns_name(name)` | one normalized entry |
| `normalize_subject_attribute(value, field_name, *, max_length)` | stripped, validated CN/O |
| `common_name_as_san(common_name)` | the SAN form of a host-like CN, else `None` |

### Intermediate CAs

A root created with `path_length=1` can sign intermediate CAs, which sign leaves; the root key is then needed only to sign intermediates and CRLs, so it can stay offline. An intermediate works wherever a CA does: pass its certificate and key as `ca_cert_pem` / `ca_key_pem` to every leaf function, `generate_crl` and `generate_ocsp_response*`.

- Intermediates always carry `path_length=0`: they sign leaves only, so the chain is at most root, intermediate, leaf.
- They inherit the issuer's Name Constraints (permitted and excluded). `permitted_subtrees` narrows them, and each entry must lie within one of the issuer's permitted subtrees; leaf issuance then enforces the narrower set.
- `organization_name=None` reuses the issuer's O. The RSA default size is `DEFAULT_CA_KEY_SIZE`.
- An intermediate may not outlive its issuer; `TinyPkiError` names the largest `validity_days` that fits.
- An issuer with `path_length=0` (every CA created before this option, and every intermediate), or whose Key Usage lacks `keyCertSign`, is refused.
- Relying parties need the chain: serve the intermediate next to each leaf (a TLS server's full chain), trust the root, and, when they check CRLs, give them the root's CRL as well as the intermediate's. `generate_pkcs12` accepts the chain as concatenated PEM.
- `sign_intermediate_csr` applies the CSR policy of [Signing a CSR](#signing-a-csr); the CSR's own `BasicConstraints` and other extensions are ignored with a `TinyPkiWarning`.

### Signing a CSR

`sign_client_csr` issues a client certificate for a key that never leaves the device (a keychain, TPM, or YubiKey), and `sign_server_csr` a server certificate for a key that never leaves the server. The CSR is PEM (including Windows `certreq`'s `NEW CERTIFICATE REQUEST` header) or DER.

- Only the CSR's public key is used. `common_name`, the organization, the validity window, and every extension come from the CA side exactly as in `generate_client_certificate` / `generate_server_certificate`, so the result is indistinguishable apart from key origin, and the same name, Name Constraints, and lifetime checks apply.
- A different CN in the CSR's subject and any extensions it requests (`BasicConstraints(ca=True)`, other extended key usages, and, for clients, SANs) are ignored, each with a `TinyPkiWarning` emitted after issuance. A CSR therefore cannot obtain a CA certificate, a certificate of the other kind, or choose its own identity.
- `sign_server_csr` takes its SANs from `san_entries` and the CN (`include_common_name_in_sans`), as `generate_server_certificate` does. The DNS names and IP addresses the CSR requests are added only with `include_csr_sans=True`; otherwise any not already covered are ignored with a `TinyPkiWarning`. Accepted CSR SANs are normalized and must satisfy the CA's Name Constraints. Requested SANs of any other type (URI, email, otherName, ...) are always ignored with a `TinyPkiWarning`, since server certificates carry only DNS and IP SANs.
- The CSR must carry a valid self-signature using SHA-256, SHA-384, or SHA-512, and an RSA key of an `ALLOWED_KEY_SIZES` size with public exponent 65537 or an ECDSA P-256 key; anything else raises `TinyPkiError` listing every problem.

`inspect_csr(csr_pem)` summarizes a CSR without signing it and returns a `CsrSummary`:

| Field | Meaning |
| --- | --- |
| `subject`, `common_name`, `sans` | what the CSR asks for (RFC 4514 subject string, its CN or `None`, DNS and IP SANs) |
| `key_type`, `key_size` | `"rsa"` with its size, `"ec-p256"` with `None`, or a description of an unsupported key |
| `signature_hash` | e.g. `"sha256"`, or `None` when unknown |
| `public_key_fingerprint` | SHA-256 of the DER SubjectPublicKeyInfo, colon-separated upper-case hex: compare it with the device owner out of band |
| `requested_extensions` | extension class names (or dotted OIDs) the CSR requests, all ignored when signing (except SANs a server signing accepts) |
| `problems` | every reason `sign_client_csr` / `sign_server_csr` would refuse the CSR; empty when it can be signed |

## Revoke

| Function | Returns |
| --- | --- |
| `generate_crl(ca_cert_pem, ca_key_pem, revoked_entries, *, validity_days=30, crl_number=None)` | CRL PEM signed by the CA, with `CRLNumber` and `AuthorityKeyIdentifier` (RFC 5280) |

`crl_number` defaults to microseconds since the epoch, which only increases if the signing host's clock never goes backwards. Pass a persisted counter if you can't guarantee that.

`revoked_entries` is a `list[tuple[int, datetime]]` of `(serial_number, revoked_at)`. The CRL's `nextUpdate` is `validity_days` from now — relying parties (nginx, OpenSSL) reject an expired CRL, so regenerate on a schedule shorter than that window. Pass the **full** revoked set every time; the CRL is not incremental.

## OCSP

tiny-pki runs no responder. These functions sign OCSP responses (RFC 6960) with the CA key from the same `revoked_entries` that `generate_crl` takes, and return DER bytes.

| Function | Returns |
| --- | --- |
| `generate_ocsp_response(ca_cert_pem, ca_key_pem, request_der, *, issued_serials, revoked_entries, validity_days=7)` | the response to one DER OCSP request: `revoked` (with its time) for a serial in `revoked_entries`, `good` for one in `issued_serials`, `unknown` for anything else. A request for another CA gets an unsigned `unauthorized` response and an unparsable one `malformedRequest`; a request nonce is echoed |
| `generate_ocsp_response_for_certificate(ca_cert_pem, ca_key_pem, cert_pem, *, revoked_entries, validity_days=7)` | a pre-signed response for one certificate issued by this CA, for a TLS server to staple (nginx `ssl_stapling_file`); `good` or `revoked`. A certificate from another CA raises `tiny_pki.ocsp.ForeignCertificateError`, a `TinyPkiError` subclass |

`validity_days` (1 to `MAX_OCSP_VALIDITY_DAYS`, 30) sets `nextUpdate`; `thisUpdate` is backdated by `CLOCK_SKEW_BACKDATE`. Responses are signed directly by the CA key (the responder ID is the CA's key hash), so answering requests online means keeping the CA key online, as renewing the CRL already does. To serve requests, call `generate_ocsp_response` (or `CertificateStore.respond_ocsp`) from your own HTTP endpoint and issue leaves with `ocsp_url` pointing at it.

## Bundle

| Function | Returns |
| --- | --- |
| `generate_pkcs12(cert_pem, key_pem, ca_cert_pem, friendly_name, password, *, legacy=False)` | PKCS#12 `bytes` (cert + key + CA chain) |

- `ca_cert_pem` is the issuing CA, optionally followed by the certificates above it (an intermediate, then its root) as concatenated PEM; every one goes into the bundle.

- `password` is `bytes` of at least `MIN_PKCS12_PASSWORD_LENGTH` (16).
- By default the bundle uses AES-256-CBC with PBKDF2-HMAC-SHA256 and an HMAC-SHA256 MAC (`cryptography`'s best available encryption).
- `legacy=True` (CLI `export p12 --legacy`) switches to 3DES with a SHA-1 MAC, for older Android or Apple keychains that can't import the modern format. Use it only when a device needs it.
- The CLI never takes the password as an argument, because arguments end up in shell/REPL history and process listings. It prompts twice (the entries must match) or reads the first line of `--password-file PATH`. After exporting from a file, it warns that the file holds the password in plaintext and, on a terminal, offers to delete it. Otherwise it leaves the file in place and says so.

## Inspect

All take a certificate as PEM or DER, detected from the input, so a TLS server can pass the DER from `SSLObject.getpeercert(binary_form=True)` directly. `check_certificate` and `check_crl` accept DER for the certificate and the CA too. Input that is neither raises `TinyPkiError` naming both formats, without echoing the bytes. These helpers only read, so they accept certificates tiny-pki would not issue, such as ones with several URI SANs. For a CSR, see `inspect_csr` under [Signing a CSR](#signing-a-csr).

| Function | Returns |
| --- | --- |
| `get_certificate_expiry(cert_pem)` | `datetime` (UTC, `notAfter`) |
| `get_certificate_fingerprint(cert_pem)` | SHA-256, colon-separated upper-case hex |
| `get_certificate_identity(cert_pem)` | `CertificateIdentity`: `common_name` (first CN, or `None`), `dns_names`, `ip_addresses`, `uris` (tuples in certificate order), `serial_number` and `fingerprint`, to authenticate a peer in one call |
| `get_certificate_issuer(cert_pem)` | issuer CN (or the full RFC 4514 DN, e.g. `OU=PKI,O=Acme,C=US`, if no CN) |
| `get_certificate_metadata(cert_pem)` | `dict` of subject fields present: `CN`, `O`, `OU`, `C`, `ST`, `L` |
| `get_certificate_sans(cert_pem)` | `list[str]` of DNS + IP SANs (empty if none); URI SANs come from `get_certificate_uris` |
| `get_certificate_serial_number(cert_pem)` | `int` |
| `get_certificate_subject(cert_pem)` | subject CN (or the full RFC 4514 DN if no CN) |
| `get_certificate_uris(cert_pem)` | `list[str]` of URI SANs, such as SPIFFE IDs, in certificate order (empty if none) |
| `is_certificate_self_signed(cert_pem)` | `True` only if issuer == subject **and** the signature verifies with its own key |

Authenticating an mTLS peer, for example in an asyncio server:

```python
from tiny_pki import get_certificate_identity

peer = get_certificate_identity(writer.get_extra_info("ssl_object").getpeercert(binary_form=True))
user = peer.uris[0] if peer.uris else peer.common_name
```

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
- With `ca_cert_pem`, a certificate not signed by that CA is `untrusted`, and a CA that expires first becomes the effective `not_after`. With `crl_pem` (which requires `ca_cert_pem`), a listed serial is `revoked`, and a CRL past its `nextUpdate` makes the result `untrusted` ("revocation status unknown"). A CRL not signed by the given CA raises `TinyPkiError` from `check_certificate` and is `untrusted` from `check_crl`.
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
| `DEFAULT_CRL_VALIDITY_DAYS` | `30`: `generate_crl` default and a store's CRL lifetime until set |
| `DEFAULT_INTERMEDIATE_VALIDITY_DAYS` | `1825`: lifetime of an intermediate CA (`generate_intermediate_ca_certificate`, `sign_intermediate_csr`) |
| `DEFAULT_KEY_TYPE` | `"rsa"` |
| `DEFAULT_LEAF_KEY_SIZE` | `3072` |
| `DEFAULT_OCSP_VALIDITY_DAYS` | `7`: OCSP response lifetime for `generate_ocsp_response*` and a store's stapling responses until set |
| `DEFAULT_ORGANIZATION_NAME` | `"tiny-pki"` |
| `DEFAULT_SERVER_VALIDITY_DAYS` | `90` |
| `KEY_TYPES` | `("rsa", "ec-p256")`; the `KeyType` literal type names the same values |
| `MAX_CA_WARNING_DAYS` | `180` |
| `MAX_CLIENT_VALIDITY_DAYS` | `825` |
| `MAX_LEAF_WARNING_DAYS` | `30` |
| `MAX_OCSP_VALIDITY_DAYS` | `30`: upper bound for an OCSP response lifetime (`ocsp --days`) |
| `MAX_SERVER_VALIDITY_DAYS` | `200` |
| `MAX_STORE_CRL_VALIDITY_DAYS` | `365`: upper bound for `init --crl-days` / `crl --days` / `CertificateStore.set_crl_validity_days` |
| `MAX_VALIDITY_DAYS` | `36500`: hard ceiling for any `validity_days` (CA, leaf, CRL), even with `allow_long_validity` |
| `MIN_PKCS12_PASSWORD_LENGTH` | `16` |
| `VALIDITY_PRESETS` | `[(90, "90 days"), …, (825, "825 days")]` for UI pickers; clamp with `max_leaf_validity_days(ca_cert_pem)` |

## Errors and warnings

`TinyPkiError` (a subclass of `ValueError`, so `except ValueError` keeps working) is raised for every input or policy rejection in `issue`, `revoke`, `bundle`, `names`, `check`, and `secrets`: a bad key size, name, or SAN, a leaf that would outlive its CA, a name-constraint violation, a short PKCS#12 password or Fernet secret, a key that is not an unencrypted RSA or P-256 key or does not match the CA certificate, a naive datetime, and so on. Its message says what was expected and what was received and never contains key material, so it is safe to show to end users.

Other `ValueError`s still come from `cryptography` itself, for example PEM or DER input that cannot be parsed at all or a wrong password when loading a PKCS#12 bundle; `tiny_pki.store` also raises plain `ValueError`, `KeyError`, and `FileNotFoundError` for store operations.

`TinyPkiWarning` (a `UserWarning`) flags certificates that were issued but that some relying parties may reject. It is emitted only once issuance has succeeded: a call that raises `TinyPkiError` emits no warnings.

## Optional: `tiny_pki.secrets`

Fernet helpers for encrypting private keys at rest. Import from the submodule:

```python
from tiny_pki.secrets import (
    decrypt_private_key,
    decrypt_private_key_scrypt,
    encrypt_private_key,
    encrypt_private_key_scrypt,
    reencrypt_private_key,
)
```

| Function | Returns |
| --- | --- |
| `encrypt_private_key(pem_data, secret, *, info=DEFAULT_INFO)` | Fernet token `bytes` |
| `decrypt_private_key(encrypted_data, secret, *, info=DEFAULT_INFO)` | PEM `bytes` (raises `cryptography.fernet.InvalidToken` on a wrong secret or `info`) |
| `reencrypt_private_key(encrypted_data, old_secret, new_secret, *, old_info=DEFAULT_INFO, new_info=DEFAULT_INFO)` | new token — use when rotating the secret or migrating off the legacy derivation |
| `derive_fernet_key(secret, *, info=DEFAULT_INFO)` | the Fernet key (`urlsafe_b64(HKDF-SHA256(secret, salt=None, info=info))`) |
| `encrypt_private_key_scrypt(pem_data, secret)` | envelope with Scrypt parameters, per-key salt, and Fernet token |
| `decrypt_private_key_scrypt(encrypted_data, secret)` | PEM `bytes` from the Scrypt envelope |

The Fernet key is derived with HKDF-SHA256 (RFC 5869) using the fixed label `DEFAULT_INFO` (`b"tiny-pki:fernet-key:v1"`). The label gives domain separation: the derived key is independent of anything else your app derives from the same secret, so passing an app-wide secret such as Django's `SECRET_KEY` does not reuse a key another component also computes. Pass a different non-empty `info` to derive further independent keys from one secret. It does **not** protect against the secret itself leaking — the label is public, so anyone holding the secret can derive the key.

`info=None` selects the legacy derivation used before HKDF (`urlsafe_b64(sha256(secret))`). Use it only to read old tokens, typically via `reencrypt_private_key(token, secret, secret, old_info=None)`; an empty `info` raises `TinyPkiError`.

HKDF does no stretching, so the secret must already be high-entropy — e.g. Django's `SECRET_KEY`, not a human password. `encrypt_private_key` and `derive_fernet_key` raise `TinyPkiError` for secrets shorter than `MIN_SECRET_LENGTH` (32 characters). The length check is a floor, not a strength test: 32 random characters are fine, 32 repeated letters are not. `decrypt_private_key` accepts any non-empty secret, so `reencrypt_private_key(token, old_weak, new_strong)` can move keys stored under an older, shorter secret.

`encrypt_private_key_scrypt` records the Scrypt parameters (`n=2^17`, `r=8`, `p=1`), generates a random 16-byte salt, and derives the Fernet key. Its matching decrypt helper validates the recorded profile before deriving the key. This slows offline guessing when a secret is weaker than intended, but does not remove the need for a long, random secret; the CLI store uses this format for encrypted CA keys.

## Optional: `tiny_pki.tls`

Builds `ssl.SSLContext` objects for mutual TLS from the PEM bytes the library returns, so callers that keep certificates in a database don't write keys to disk themselves. `import tiny_pki` does not import it:

```python
from tiny_pki.tls import client_context, server_context
```

| Function | Returns |
| --- | --- |
| `server_context(cert_pem, key_pem, ca_cert_pem, *, crl_pem=None, client_cert="required", crl_check=None, max_tls_version=None)` | `ssl.SSLContext` (`PROTOCOL_TLS_SERVER`) presenting `cert_pem` and verifying client certificates against `ca_cert_pem` |
| `client_context(cert_pem, key_pem, ca_cert_pem, *, server_hostname_check=True, max_tls_version=None)` | `ssl.SSLContext` (`PROTOCOL_TLS_CLIENT`) presenting `cert_pem` and verifying the server against `ca_cert_pem` |

- `cert_pem` is the leaf, optionally followed by intermediate CA certificates; `key_pem` must be an unencrypted RSA or ECDSA P-256 key matching it. `ca_cert_pem` holds one or more trusted CA certificates. System CAs are never loaded, so only your CA is trusted.
- `client_cert` is `"required"` (the default), `"optional"` or `"none"`. With `crl_pem` (one or more PEM CRLs, such as a store's `public/crl.pem`), revoked client certificates are refused. `crl_check` then defaults to `"leaf"`; `"chain"` also checks intermediate CAs and needs a CRL from every CA in the chain. `crl_check="leaf"` or `"chain"` without `crl_pem`, `crl_check="none"` with it, or `crl_pem` with `client_cert="none"` raise `TinyPkiError` rather than silently skip the check. Load a fresh context after each CRL publish.
- The minimum version is TLS 1.2; `max_tls_version` (`ssl.TLSVersion.TLSv1_2` or later) caps it. Clients check the server's SANs against the `server_hostname` they connect with unless `server_hostname_check=False`; the certificate is verified either way.
- The CA certificates load from memory (`cadata`). `load_cert_chain` only reads files, and `cadata` silently ignores CRLs, so the certificate, key and CRL are written to a temporary directory (mode `0700`, files `0600`) that is removed before the call returns or raises.
- Malformed PEMs, encrypted or mismatched keys and chains OpenSSL refuses raise `TinyPkiError` without echoing the input.

An amqtt listener takes the context as `ssl_context` (added in [Yakifo/amqtt#396](https://github.com/Yakifo/amqtt/pull/396); it replaces the listener's other TLS options). amqtt requires a `default` listener; its `bind` of `None` keeps it from also opening a plaintext port beside the mTLS one:

```python
from amqtt.broker import Broker
from tiny_pki.tls import server_context

broker = Broker(
    {
        "listeners": {
            "default": {"type": "tcp", "bind": None},
            "mtls": {
                "type": "tcp",
                "bind": "0.0.0.0:8883",
                "ssl": True,
                "ssl_context": server_context(server_pem, server_key, ca_pem, crl_pem=crl_pem),
            },
        },
    }
)
await broker.start()
```

For the client side, pass `client_context(client_pem, client_key, ca_pem)` wherever the client library accepts an `ssl.SSLContext`, for example `asyncio.open_connection(host, 8883, ssl=ctx, server_hostname=host)`.

## Optional: `tiny_pki.store`

`CertificateStore(root)` is the filesystem store the CLI uses. Its `issue_client` / `issue_server` / `revoke` / `delete` / `publish_crl` / `publish_ocsp` methods and `check_store(store, ...)` do what the matching CLI verbs do and keep `crl.pem` in step with `index.json`. Library callers that keep certificates in their own database don't need it; it is documented in [`store.md`](store.md#using-the-store-from-python).
