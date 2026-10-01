# Command-line reference

`tiny-pki` runs one command and exits, or, with no command, opens a REPL that accepts the same commands. Install it with the `cli` extra (`pipx install 'tiny-pki[cli]'` or `uv tool install 'tiny-pki[cli]'`).

```text
tiny-pki [--store DIR] [--color auto|always|never] [--edit-mode vim|emacs] [COMMAND [ARGS...]]
```

`help` lists the commands and `help COMMAND` prints one command's usage and flags; both work in the REPL and as one-shot commands. The files a store holds are described in [store.md](store.md), and the defaults behind each flag in [defaults.md](defaults.md).

- [Global options](#global-options)
- [Identities](#identities)
- [Exit status](#exit-status)
- Commands: [init](#init), [create](#create), [sign](#sign), [list](#list), [show](#show), [inspect](#inspect), [export](#export), [revoke](#revoke), [delete](#delete), [crl](#crl), [ocsp](#ocsp), [encrypt-key](#encrypt-key), [decrypt-key](#decrypt-key), [check](#check), [completion](#completion), [REPL commands](#repl-commands)
- Workflows: [enrolling a device from a CSR](#enrolling-a-device-from-a-csr), [rotating a client certificate](#rotating-a-client-certificate), [a lost device or compromised key](#a-lost-device-or-a-compromised-key), [serving mTLS from nginx](#serving-mtls-from-nginx), [stapling OCSP from nginx](#stapling-ocsp-from-nginx), [renewing the CRL on a timer](#renewing-the-crl-on-a-timer), [running an intermediate CA](#running-an-intermediate-ca)

## Global options

| Option | Meaning |
| --- | --- |
| `--store DIR` | The store directory. `TINY_PKI_STORE` is used when the flag is absent. Every command that reads or writes the store needs one; there is no default, and an empty value or `.` is refused. |
| `--color auto\|always\|never` | Colour output. `auto` (the default) colours only a terminal, and `NO_COLOR` turns colour off. Use `never` in scripts and cron jobs. |
| `--edit-mode vim\|emacs` | REPL key bindings (default `vim`, or `TINY_PKI_EDIT_MODE`). |
| `--version` | Print the version and the commit it was built from, then exit. |
| `--help` | Print the launcher options. |

The REPL keeps its history in `~/.cache/tiny-pki/history` (mode `0600`).

## Identities

Commands that take a `NAME` accept a common name, matched case-insensitively, or a hex serial with or without `0x`. A value that is one certificate's serial and another certificate's name is refused as ambiguous, and the error suggests an unambiguous form. While two live certificates share a name (after `create client --keep-previous`), `show`, `inspect` and `export` use the newer one, and `revoke` and `delete` refuse the name and ask for `0xSERIAL`.

## Exit status

Commands exit `0` on success and `1` on an error, which is printed on stderr. Two commands differ. `completion` exits `2` on a usage error (a missing or unknown shell, an unknown flag, or `--force` without `--install`). `check` uses monitoring-plugin codes: `0` everything ok, `1` something expiring, `2` something expired, not yet valid, revoked or untrusted, and `3` when the check could not run. Flags and arguments are validated before anything is written, so a rejected command leaves the store unchanged.

## Commands

### init

```text
tiny-pki --store DIR init [options]
```

Creates the CA certificate and key under `ca/`, publishes an empty CRL, and fills `public/` with key-free copies for TLS servers. Refuses a store that already has a CA.

By default the CA signs leaves only. `--path-length 1` creates a root that may also sign intermediate CAs, and `--intermediate-of DIR` creates this store's CA as an intermediate signed by the root in `DIR`: the root records the certificate (with no key) under `intermediates/`, and this store gets the key, the chain (`ca/chain.pem`), the root's CRL and its own first CRL. An intermediate inherits the root's name constraints, `--permit` narrows them, and it signs leaves only. See [running an intermediate CA](#running-an-intermediate-ca).

| Flag | Meaning |
| --- | --- |
| `--cn NAME` | CA common name (default `Private CA`, or `Intermediate CA` with `--intermediate-of`). |
| `--org NAME` | Organization (O); leaves inherit it (default `tiny-pki`, or the issuer's with `--intermediate-of`). |
| `--days N` | CA validity in days (default 3650, or 1825 for an intermediate, which may not outlive its issuer). Leaves may not outlive the CA. |
| `--path-length 0\|1` | `1` lets the CA sign intermediate CAs; `0` (the default) limits it to leaves. It cannot be changed later. Refused with `--intermediate-of`. |
| `--intermediate-of DIR` | Create an intermediate CA signed by the CA in the store at `DIR`, which must have been created with `--path-length 1`. |
| `--issuer-key-secret-file PATH` | With `--intermediate-of`: read the issuer's CA-key secret from the first line of this file when its key is encrypted (otherwise it is prompted for). |
| `--key-type rsa\|ec-p256` | Key algorithm (default `rsa`). See [security.md](security.md#key-types-sizes-and-validity). |
| `--key-size 2048\|3072\|4096` | RSA key size (default 4096). Refused with `--key-type ec-p256`. |
| `--permit NAME` | Add a Name Constraint: a DNS suffix (`home` covers `home` and every name under it) or an IP network (`192.168.0.0/16`). Repeat it for each; constrain both DNS and IP (see [security.md](security.md#limit-what-the-ca-can-vouch-for)). Constraints cannot be changed later. For an intermediate, each must lie within the issuer's. |
| `--permit-uri HOST` | Add a URI Name Constraint, so the CA may issue client certificates with a `--uri-san`. `example.home` permits URIs whose host is exactly `example.home`; `.example.home` permits any host under it. Repeat it for each. Once a CA has any `--permit`, a URI SAN needs a matching `--permit-uri`. |
| `--crl-days N` | CRL lifetime in days, 1–365 (default 7), saved in the store and used by every later publish. |
| `--encrypt-key` | Encrypt `ca/ca.key` at rest when creating the CA; the secret is read from `--key-secret-file`, a configured credential file, or an interactive prompt. |
| `--key-secret-file PATH` | Read the high-entropy CA-key secret from the first line of this file; use only with `--encrypt-key` for `init`. |

```bash
tiny-pki --store ./stores/ca init --cn "Home CA" --permit home --permit 192.168.0.0/16
tiny-pki --store ./stores/root init --cn "Home Root" --path-length 1 --permit home --encrypt-key
tiny-pki --store ./stores/mqtt init --cn "MQTT CA" --permit home --permit-uri example.home
tiny-pki --store ./stores/issuing init --intermediate-of ./stores/root --cn "Home Issuing"
```

### create

```text
tiny-pki --store DIR create client|server NAME [options]
```

Issues a client certificate (`CLIENT_AUTH`, identified by its CN) or a server certificate (`SERVER_AUTH`, identified by its SANs) and records it in the index. Re-issuing a name that has a live certificate revokes the old one and republishes the CRL, unless `--keep-previous` is given.

| Flag | Meaning |
| --- | --- |
| `--days N` | Validity in days (default 397 for clients, 90 for servers; capped at 825 and 200). |
| `--key-secret-file PATH` | Read the CA-key secret from the first line of a file when the CA key is encrypted. |
| `--allow-long-validity` | Allow a validity beyond the cap. Apple platforms reject server certificates over 825 days, and tiny-pki warns. |
| `--key-type rsa\|ec-p256` | Key algorithm (default `rsa`). It may differ from the CA's. |
| `--key-size 2048\|3072\|4096` | RSA key size (default 3072). Refused with `--key-type ec-p256`. |
| `--org NAME` | Organization (O); defaults to the CA's. |
| `--allow-dn-special-chars` | Allow `,` `+` `=` `"` `<` `>` `;` or a leading `#` in the name. They are refused by default because `bob,CN=alice` would end in `,CN=alice` in the DN string nginx and Mosquitto match. |
| `--keep-previous` | Clients only: keep the previous certificate live, for [rotation](#rotating-a-client-certificate). |
| `--uri-san URI` | Clients only: add one URI SAN (see [client URI SANs](#client-uri-sans)). |
| `--san NAME` | Servers only: a DNS name or IP address. Repeat it for each; without it the CN is the only SAN. |
| `--yes` | Servers only: add a host-like CN that is missing from `--san` without asking. |
| `--no-cn-san` | Servers only: never add the CN to the SANs (needs `--san`). |

TLS clients ignore the CN, so when a server's CN is a host name or IP address missing from `--san`, `create` asks whether to add it. `--yes` and a non-interactive stdin add it, and `--no-cn-san` leaves it out.

```bash
tiny-pki --store ./stores/ca create client alice --days 730
tiny-pki --store ./stores/ca create client phone --key-type ec-p256
tiny-pki --store ./stores/ca create client sensor-1 --uri-san spiffe://example.home/device/sensor-1
tiny-pki --store ./stores/ca create server api.home --san api.home --san 192.168.1.10
```

### sign

```text
tiny-pki --store DIR sign client|server|intermediate NAME --csr PATH [options]
```

Issues a certificate for a certificate signing request (CSR) generated where the key lives, so the private key never reaches the CA host: a laptop keychain, a TPM, or a YubiKey for `client`, or the server itself (nginx, Mosquitto, an internal service) for `server`. The store records the certificate with no key file. Only the CSR's public key is used. The CN is always `NAME`, and every extension comes from the same profile `create client` or `create server` uses; a different CN or any extensions the CSR requests are ignored with a warning. The CSR (PEM, including Windows `certreq`'s `NEW CERTIFICATE REQUEST` header, or DER) must have a valid signature using SHA-256 or stronger, and an RSA 2048/3072/4096 key with public exponent 65537 or an ECDSA P-256 key. Re-signing a name that has a live certificate revokes the old one, as for `create`. See [enrolling a device from a CSR](#enrolling-a-device-from-a-csr).

`sign intermediate` issues an intermediate CA certificate for a CA whose key lives elsewhere, such as OpenBao (`pki/intermediate/generate/internal`), from a store created with `--path-length 1`. It has the same profile as `init --intermediate-of`: `BasicConstraints` CA with path length 0, `keyCertSign` and `cRLSign`, the store's name constraints (narrowed by `--permit`), and a lifetime within the store CA's (default 1825 days). The CSR's own `BasicConstraints` and other extensions are ignored with a warning. Give the intermediate this store's `public/ca.crt` (its chain) and keep its CRL reachable, since relying parties that check revocation check it too. A renewed intermediate does not revoke the previous one, whose leaves still chain to it; revoke that by serial once they are replaced.

A server certificate's SANs come from `--san` and the CN, exactly as for `create server` (including the CN-in-SAN prompt). The DNS names and IP addresses the CSR requests are never taken silently: when some are not already covered, `sign server` asks whether to include them, defaulting to no. `--accept-csr-sans` includes them without asking, and a non-interactive stdin leaves them out with a warning. Included CSR SANs are normalized and checked against the CA's name constraints like any other. Requested SANs of other types (URI, email, otherName, ...) are always left out with a warning.

| Flag | Meaning |
| --- | --- |
| `--csr PATH` | The certificate signing request (required). |
| `--days N` | Validity in days (default 397 for clients, 90 for servers, 1825 for intermediates; leaves are capped at 825 and 200). |
| `--allow-long-validity` | Leaves only: allow a validity beyond the cap, as for `create`. |
| `--org NAME` | Organization (O); defaults to the CA's. |
| `--allow-dn-special-chars` | Leaves only: allow `,` `+` `=` `"` `<` `>` `;` or a leading `#` in the name, as for `create`. |
| `--permit NAME` | Intermediates only: narrow the name constraints to this DNS suffix or IP network, within the store CA's. Repeat it for each. |
| `--permit-uri HOST` | Intermediates only: narrow the URI name constraints to this host (`.example.home` for hosts under it), within the store CA's. Repeat it for each. |
| `--keep-previous` | Clients only: keep the previous certificate live, for [rotation](#rotating-a-client-certificate). |
| `--uri-san URI` | Clients only: add one URI SAN (see [client URI SANs](#client-uri-sans)). The CSR's own SANs are still ignored. |
| `--san NAME` | Servers only: a DNS name or IP address. Repeat it for each; without it the CN is the only SAN. |
| `--accept-csr-sans` | Servers only: also include the SANs the CSR requests, without asking. |
| `--yes` | Servers only: add a host-like CN that is missing from `--san` without asking. |
| `--no-cn-san` | Servers only: never add the CN to the SANs (needs `--san`). |
| `--key-secret-file PATH` | Read the CA-key secret from the first line of a file when the CA key is encrypted. |
| `--out PATH` | Also write the issued certificate (mode `0644`) to this file for the device or server. |

```bash
tiny-pki --store ./stores/ca inspect laptop.csr        # compare the public key fingerprint with the device
tiny-pki --store ./stores/ca sign client alice-laptop --csr laptop.csr --out alice-laptop.crt
tiny-pki --store ./stores/ca sign server api.home --csr api.csr --san api.home --san 192.168.1.10 --out api.crt
tiny-pki --store ./stores/root sign intermediate "OpenBao Issuing" --csr bao.csr --permit svc.home --out bao.crt
```

#### Client URI SANs

`--uri-san URI` gives a client certificate one URI SAN next to its CN, for brokers and services that identify clients by URI, such as SPIFFE IDs or amqtt's `UserAuthCertPlugin`, which reads the username from the URI SAN. The URI must be absolute, with a scheme and a host, and must not contain user info (`user@`), a query, a fragment, whitespace or non-ASCII characters. For `spiffe://` URIs the trust domain is lower-case letters, digits, `.`, `-` and `_` with no port, and every path segment is letters, digits, `.`, `-` or `_` (not `.` or `..`). The scheme is lower-cased; nothing else is changed. A CA with name constraints needs a matching `--permit-uri` at `init`.

The URI is recorded in `index.json` as `uri_san`, shown by `list` (and `list --json`) and printed by `inspect`. A `--keep-previous` rotation keeps the previous certificate's URI on its entry; give the new certificate the same `--uri-san` so the broker maps it to the same identity.

amqtt's `UserAuthCertPlugin` (`amqtt.contrib.cert`) accepts a client whose first URI SAN is `spiffe://<uri_domain>/device/<id>` and whose MQTT `client_id` is `<id>`. To check a certificate by hand, run a TLS listener with `cafile` set to the store's `public/ca.crt`, `client_cert: required` and the plugin's `uri_domain: example.home`, then connect with `client_id` `sensor-1` and the certificate from `create client sensor-1 --uri-san spiffe://example.home/device/sensor-1`. The connection is accepted; a different `client_id` is refused.

### list

```text
tiny-pki --store DIR list [ca|certs|clients|servers|intermediates|revoked] [--json]
```

With no argument, prints a summary: the CA name and how many clients, servers, intermediate CAs and revoked certificates the store holds. `clients`, `servers` and `intermediates` list live certificates, `revoked` lists revoked ones (including deleted tombstones), `certs` lists everything that still has files, and `ca` shows the CA, the chain above it (for an intermediate), its CRL lifetime and the paths TLS servers need. A live certificate that a newer one for the same name replaces is marked "superseded by".

| Flag | Meaning |
| --- | --- |
| `--json` | Print JSON instead; the fields are listed in [store.md](store.md#list---json). |

### show

```text
tiny-pki --store DIR show ca|certs|clients|servers|intermediates|revoked [--json]
tiny-pki --store DIR show crl|NAME
```

`show` with a category is the same as `list` with it, including `--json`. `show crl` and `show NAME` take no flags. `show crl` lists the revoked serials in the current CRL, and `show NAME` prints one certificate's subject, issuer, serial, expiry, fingerprint and SANs.

### inspect

```text
tiny-pki [--store DIR] inspect NAME|PATH
```

Prints a certificate's details. A path to a PEM file needs no store; for a store identity, `inspect` also checks the certificate against the store's CA and CRL.

For a CSR file, `inspect` prints the requested subject and SANs, the key type and size, the signature hash, any requested extensions (all ignored by `sign`), the SHA-256 fingerprint of the public key, and whether `sign` would accept it, listing each reason when it would not.

### export

```text
tiny-pki --store DIR export pem|p12 NAME [options]
tiny-pki --store DIR export pem NAME [--out PATH | --cert-out PATH --key-out PATH] [--ca-out PATH]
```

`pem` writes the certificate and private key to one file (default `NAME.pem` in the current directory), or to separate files with `--cert-out` and `--key-out`. `p12` writes a password-protected PKCS#12 bundle with the certificate, key and CA (plus the chain above it, for an intermediate CA), for phones and browsers (default `bundles/NAME-SERIAL.p12` in the store). Files holding a private key are written with mode `0600`, certificate-only files with `0644`, and a destination that is a symlink is refused.

For a certificate issued by [`sign`](#sign), and for an intermediate CA, the store has no private key: `pem` writes the certificate alone (mode `0644`), `--key-out` is refused (`--cert-out` alone works), and `p12` is refused.

| Flag | Meaning |
| --- | --- |
| `--out PATH` | Write to this file instead of the default. |
| `--cert-out PATH` | `pem`: write the certificate (mode `0644`) to this file. Give it with `--key-out`, not with `--out`. |
| `--key-out PATH` | `pem`: write the private key (mode `0600`) to this file. Give it with `--cert-out`, not with `--out`. |
| `--ca-out PATH` | `pem`: also write the CA certificate (mode `0644`) to this file: the bytes of `public/ca.crt`, or of `public/ca-chain.pem` (the CA followed by the CAs above it) for an intermediate CA. Works with the combined and the split form. |
| `--password-file PATH` | `p12`: read the password (at least 16 bytes) from the first line of this file instead of prompting. The CLI then offers to delete the file. |
| `--legacy` | `p12`: use 3DES with a SHA-1 MAC for older Android and Apple keychains that cannot import the default AES-256 bundle. |

The password is never taken as an argument, because arguments end up in shell history and process listings. Without `--password-file`, `export p12` prompts twice.

Every destination is checked before anything is written: two outputs may not share a path, and each must be a file in an existing directory. The files are staged next to their destinations and renamed into place only once all of them are written, so a failed export leaves existing files unchanged. If a rename fails after earlier ones succeeded, those files are put back and any it newly created are removed.

Split files suit TLS software configured with separate `certfile`, `keyfile` and `cafile` settings:

```bash
tiny-pki --store ./stores/ca export pem mqtt.home --cert-out broker.crt --key-out broker.key --ca-out ca.crt
tiny-pki --store ./stores/ca export pem sensor-1 --cert-out sensor-1.crt --key-out sensor-1.key --ca-out ca.crt
```

A Mosquitto listener that requires client certificates and uses the CN as the username, and a client:

```text
listener 8883
cafile /etc/mosquitto/pki/ca.crt
certfile /etc/mosquitto/pki/broker.crt
keyfile /etc/mosquitto/pki/broker.key
crlfile /etc/mosquitto/pki/crl.pem
require_certificate true
use_identity_as_username true
```

```bash
mosquitto_pub -h mqtt.home -p 8883 --cafile ca.crt --cert sensor-1.crt --key sensor-1.key -t sensors/1 -m hello
```

amqtt has no YAML equivalent in a release yet: as of v0.12.1 a listener cannot require client certificates or check a CRL, and the options for both (`client_cert`, `crlfile`, `crl_check`, `ssl_context`) are on its `main` branch only. Once a release has them, [`tiny_pki.tls`](api.md#optional-tiny_pkitls) builds the same context for `ssl_context`; until then use Mosquitto or nginx for mTLS.

For Mosquitto, copy `public/crl.pem` alongside the other files after each revoke or CRL publish and reload the broker.

### revoke

```text
tiny-pki --store DIR revoke NAME|0xSERIAL [--dry-run] [--key-secret-file PATH]
```

Marks the certificate revoked and republishes `ca/crl.pem` and `public/crl.pem`. Reload the TLS server afterwards so it reads the new CRL.

| Flag | Meaning |
| --- | --- |
| `--dry-run` | Say what would be revoked and write nothing. |
| `--key-secret-file PATH` | Read the CA-key secret from the first line of a file when the CA key is encrypted. |

### delete

```text
tiny-pki --store DIR delete NAME|0xSERIAL [--force] [--dry-run] [--key-secret-file PATH]
```

Removes a revoked certificate's files. The index keeps a tombstone with the serial, so the CRL still lists it.

| Flag | Meaning |
| --- | --- |
| `--force` | Revoke an active certificate first, then delete it. Without it, deleting an active certificate is refused. |
| `--dry-run` | Say what would be deleted (and revoked) and write nothing. |
| `--key-secret-file PATH` | Read the CA-key secret from the first line of a file when the CA key is encrypted. |

### crl

```text
tiny-pki --store DIR crl [--days N] [--chain-crl PATH] [--key-secret-file PATH]
tiny-pki --store DIR crl hook [COMMAND | --clear]
tiny-pki --store DIR crl url [URL | --clear]
```

Signs a fresh CRL from the index and writes it to `ca/crl.pem` and `public/crl.pem` (which, for an intermediate CA, also holds the CRLs of the CAs above it). `renew-crl` is an alias. Run it on a timer well inside the CRL lifetime: once the CRL expires, nginx rejects every client (see [renewing the CRL on a timer](#renewing-the-crl-on-a-timer)).

| Flag | Meaning |
| --- | --- |
| `--days N` | Change the stored CRL lifetime (1–365 days) and use it for this and every later publish. |
| `--clear` | With `hook` or `url`: remove the setting. |
| `--chain-crl PATH` | Intermediate CA only: first import the new CRL(s) of the CAs above it (PEM or DER; the issuer store's `public/crl.pem` works). Each must be signed by a CA in the chain and may not be older than the one it replaces. |
| `--key-secret-file PATH` | Read the CA-key secret from the first line of a file when the CA key is encrypted. |

Once `ocsp` has published stapling responses, `crl` refreshes them too.

`crl hook COMMAND` saves a command the CLI runs after any command that changed `public/crl.pem` or the stapled OCSP responses: `crl` itself, `revoke`, `create`, `sign`, `delete` and `ocsp`. Use it to reload the TLS servers that read the CRL, so revocation takes effect at once rather than at the next timer run. Give the command as one quoted argument. It is split like a shell would split it but run without a shell (use `sh -c '...'` for pipes or `&&`), in the store root, with `TINY_PKI_STORE`, `TINY_PKI_CRL` (the path of `public/crl.pem`) and `TINY_PKI_OCSP_DIR` added to its environment, and a limit of 120 seconds. If it fails, the command that published still took effect; the CLI prints an error and exits 1 so a timer notices. `crl hook` alone prints the saved command, and `crl hook --clear` removes it. The command is saved in plain text in `ca/publishhook`, so keep tokens and passwords out of it: read them from a file or the environment inside the script it runs. The CLI does not echo the command when it runs the hook or when it fails.

`crl url URL` writes a CRL Distribution Points extension with that `http://` or `https://` URL into every certificate issued afterwards, for clients and servers that fetch the CRL themselves. An HTTP CRL Distribution Points URL must serve one DER-encoded CRL, but tiny-pki writes PEM, so serve a DER copy of `ca/crl.pem` (this CA's own CRL; for an intermediate, `public/crl.pem` also holds its issuers' CRLs, which belong at their own URLs) and refresh it after every publish, for example from `crl hook`. Certificates already issued keep what they were issued with. `crl url` alone prints the URL, and `crl url --clear` stops adding the extension.

```bash
tiny-pki --store /srv/pki/home-ca crl hook 'systemctl reload nginx'
tiny-pki --store /srv/pki/home-ca crl hook "sh -c 'cp \"\$TINY_PKI_CRL\" /etc/mosquitto/pki/crl.pem && systemctl reload mosquitto'"
tiny-pki --store /srv/pki/home-ca crl url http://pki.home/ca.crl
tiny-pki --store /srv/pki/home-ca crl hook "sh -c 'openssl crl -in ca/crl.pem -outform DER -out /var/www/pki/ca.crl'"
```

tiny-pki does not publish delta CRLs: OpenSSL-based servers such as nginx and Mosquitto would silently ignore them (see [security.md](security.md#revocation-only-works-if-the-crl-is-fresh)).

### ocsp

```text
tiny-pki --store DIR ocsp [publish] [--days N] [--key-secret-file PATH]
tiny-pki --store DIR ocsp disable
tiny-pki --store DIR ocsp url [URL | --clear]
```

tiny-pki runs no OCSP responder; this command covers the parts that need none. `ocsp` (or `ocsp publish`) signs an OCSP response for every server certificate and writes it to `public/ocsp/<cn>.der`, for nginx's `ssl_stapling_file` (see [stapling OCSP from nginx](#stapling-ocsp-from-nginx)). The file name stays the same when the certificate is renewed. A revoked server certificate that has not been deleted gets a `revoked` response. From then on `create`, `sign`, `revoke` and `delete` refresh the responses of the server certificate's CN together with the CRL, so a revocation reaches the stapled response at the same moment, and `crl` refreshes all of them. Responses are valid for 7 days by default; keep the CRL timer well inside that. `ocsp disable` stops publishing them and removes the responses and `public/ocsp/` (the directory stays if something else was put in it).

`ocsp url URL` records an `http://` or `https://` OCSP responder URL, which every certificate issued afterwards carries in its Authority Information Access extension; certificates already issued are unchanged. Only set it if something answers at that URL, such as your own endpoint built on `CertificateStore.respond_ocsp` ([store.md](store.md#using-the-store-from-python)). `ocsp url` prints the current URL, and `ocsp url --clear` stops adding one.

| Flag | Meaning |
| --- | --- |
| `--days N` | `publish` only: change the stored response lifetime (1–30 days) and use it for this and every later refresh. |
| `--key-secret-file PATH` | `publish` only: read the CA-key secret from the first line of a file when the CA key is encrypted. |
| `--clear` | `url` only: stop writing an OCSP URL into new certificates. |

### encrypt-key

```text
tiny-pki --store DIR encrypt-key [--key-secret-file PATH]
```

Encrypts an existing plaintext CA private key in place under the store lock using a per-key salt and Scrypt-derived Fernet key. Use a long, random secret; Scrypt slows offline guesses but does not make a weak secret strong. On a terminal, the secret is prompted for twice; non-interactive runs must provide a file or credential. After encryption, the CLI offers to remove an explicitly supplied `--key-secret-file` as a temporary plaintext copy. Removal defaults to No, and is refused when the file is configured as `TINY_PKI_KEY_SECRET_FILE` or is under `$CREDENTIALS_DIRECTORY`. Confirm removal only after ensuring the secret is safely available for future signing; non-interactive runs leave the file in place and warn.

| Flag | Meaning |
| --- | --- |
| `--key-secret-file PATH` | Read the new high-entropy secret from the first line of a file. |

### decrypt-key

```text
tiny-pki --store DIR decrypt-key [--key-secret-file PATH]
```

Decrypts an encrypted CA private key in place under the store lock. A missing or incorrect secret leaves the encrypted key unchanged.

| Flag | Meaning |
| --- | --- |
| `--key-secret-file PATH` | Read the existing secret from the first line of a file. |

### CA key secret sources

Signing commands automatically prompt for the CA-key secret when the store key is encrypted and stdin is a terminal. For unattended use, pass `--key-secret-file PATH`, set `TINY_PKI_KEY_SECRET_FILE` to a file path, or provide the systemd credential `tiny-pki-key` under `$CREDENTIALS_DIRECTORY`; the secret itself is never accepted as an argument. An explicit `--key-secret-file` on a plaintext store is an error; ambient environment and systemd credential settings are ignored because no secret is needed. The file's first UTF-8 line is used, and tiny-pki warns if the file has group/other access permissions. tiny-pki does not delete a secret file used for signing because later signing operations need the same secret. If you use a temporary staging file to initialize or encrypt the CA key, the CLI offers to remove an explicitly supplied `--key-secret-file` after encryption, with removal defaulting to No; it will not delete the configured environment secret file or files under `$CREDENTIALS_DIRECTORY`. Read-only commands such as `list`, `show`, `check`, and `export pem` do not need the secret.

For a systemd service, provision an encrypted credential and name it `tiny-pki-key` so systemd exposes it at `$CREDENTIALS_DIRECTORY/tiny-pki-key`:

```bash
systemd-creds encrypt --name=tiny-pki-key --with-key=host /secure/path/ca-key-secret /etc/credstore.encrypted/tiny-pki-key
```

Add this to the service unit (adjust the executable and store paths for your host):

```ini
[Service]
LoadCredentialEncrypted=tiny-pki-key:/etc/credstore.encrypted/tiny-pki-key
ExecStart=/usr/local/bin/tiny-pki --store /srv/pki/home-ca --color never crl
```

`systemd-creds encrypt` reads the source file and writes a credential encrypted with this host's systemd credential key. Protect the source secret file during provisioning and remove it securely when it is no longer needed; the encrypted credential is host-bound and is not a portable backup. A TPM2-backed credential can be chosen instead where its hardware and recovery trade-offs are appropriate. At service start, systemd decrypts the credential and makes its plaintext available to the service as a file, which tiny-pki reads. This avoids putting the secret in unit text, environment variables, command arguments, or logs, but it does not keep the secret hidden from the service itself, its privileged parent/root, or an attacker who compromises the service while it is running. Back up the encrypted CA key and its secret-recovery material separately; losing either can make the CA unable to sign.

### check

```text
tiny-pki --store DIR check [options]
tiny-pki check PATH... [options]
```

Flags expired, expiring, not-yet-valid, revoked and untrusted certificates and CRLs, soonest expiry first, and exits with a monitoring-plugin code. Without a path it checks the store's CA, CRL and every live leaf; for an intermediate CA, also each certificate above it (`issuer NAME`) and its imported CRL (`issuer crl NAME`, `untrusted` when missing), and for a root, the intermediate CAs it signed (kind `ca`). With paths it checks files instead and needs no store: PEM or DER certificates, chain files, CRLs, PKCS#12 bundles, and directories (one level deep). [monitoring.md](monitoring.md) has the output format, JSON schema and cron / systemd recipes.

| Flag | Meaning |
| --- | --- |
| `--within DAYS` | Alert on anything expiring within DAYS. By default the window is a third of each certificate's lifetime (capped at 30 days for leaves and 180 for the CA). |
| `--by YYYY-MM-DD` | Alert on anything expiring by the end of that day (local time). With `--within`, the earlier cutoff wins. |
| `--kind ca\|client\|server\|crl` | Only report this kind; repeat it for several. |
| `--include-revoked` | Store only: also report revoked certificates. |
| `--quiet` | Print only rows that need attention, and nothing when everything is ok. |
| `--json` | Print JSON instead of a table. |
| `--ca PATH` | Files only: flag certificates and CRLs not issued by this CA. |
| `--crl PATH` | Files only (needs `--ca`): report certificates listed in this CRL as revoked. |
| `--password-file PATH` | Files only: password for PKCS#12 bundles. |
| `--crl-renewal DURATION` | How often a timer renews the CRL, in hours or days (`12h`, `1d`). A CRL that expires before the next renewal, or whose lifetime is under twice the interval (so one missed run lets it lapse), is reported as expiring. |

### completion

```text
tiny-pki completion bash|zsh|fish [--install] [--force] [--json]
```

Prints a shell completion script. It completes commands, each command's flags, and flag values such as `--key-type rsa|ec-p256`; the REPL completes the same way and also offers store names.

| Flag | Meaning |
| --- | --- |
| `--install` | Write the script to the per-user completion directory instead of printing it. Re-running it is harmless. |
| `--force` | With `--install`: overwrite an existing script that differs. |
| `--json` | Report the installed path (or the script) as JSON. |

```bash
tiny-pki completion bash --install   # ~/.local/share/bash-completion/completions/tiny-pki.bash
tiny-pki completion zsh --install    # ~/.local/share/zsh/site-functions/_tiny-pki; put that directory on $fpath before compinit
tiny-pki completion fish --install   # ~/.config/fish/completions/tiny-pki.fish
```

`XDG_DATA_HOME` and `XDG_CONFIG_HOME` move those directories. Open a new shell afterwards, and keep `tiny-pki` on `PATH`.

### REPL commands

| Command | Meaning |
| --- | --- |
| `help [COMMAND]` | List the commands, or show one command's usage and flags. |
| `edit-mode [vim\|emacs]` | Show or switch the key bindings. |
| `clear` | Clear the screen. |
| `exit`, `quit` | Leave the REPL (Ctrl-D also works). |

## Workflows

### Enrolling a device from a CSR

Devices that can generate their own key and CSR, such as laptops, desktops and hardware tokens, keep the key to themselves; only the CSR and the issued certificate travel, and neither is secret. Phones and tablets usually cannot produce a CSR for browser client authentication, so they keep using `create client` and `export p12`.

1. On the device, generate a key and a CSR (EC P-256 or RSA 3072). With OpenSSL:

   ```bash
   openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
     -keyout alice-laptop.key -subj "/CN=alice-laptop" -out alice-laptop.csr
   ```

   On a YubiKey, the key is generated on the token and never leaves it:

   ```bash
   ykman piv keys generate --algorithm ECCP256 9a pubkey.pem
   ykman piv certificates request --subject "CN=alice-laptop" 9a pubkey.pem alice-laptop.csr
   ```

   macOS Keychain Access (Certificate Assistant, "Request a Certificate From a Certificate Authority", saved to disk) and Windows `certreq -new` with a non-exportable TPM key also produce CSRs.

2. Copy the CSR to the CA host and compare its public key fingerprint with the device owner over another channel (read it aloud, for example), so a substituted CSR is caught. `inspect` prints it as colon-separated upper-case hex; on the device, the same SHA-256 in lower-case hex is:

   ```bash
   openssl req -in alice-laptop.csr -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256
   ```

3. Sign it. The CN comes from the command line, never from the CSR, so a device cannot pick a name that an nginx `map` or allow-list trusts:

   ```bash
   tiny-pki --store ./stores/ca inspect alice-laptop.csr
   tiny-pki --store ./stores/ca sign client alice-laptop --csr alice-laptop.csr --out alice-laptop.crt
   ```

4. Copy `alice-laptop.crt` (and `public/ca.crt` if the device should trust the CA) back and install it next to the key: `ykman piv certificates import 9a alice-laptop.crt`, a double-click into the macOS keychain, `certreq -accept` on Windows, or the browser's certificate store alongside the OpenSSL key.

Renew with a fresh CSR and `sign ... --keep-previous`, then revoke the old serial as in [rotating a client certificate](#rotating-a-client-certificate). `revoke`, `list`, `check` and the CRL work as for any other certificate.

A server enrolls the same way with `sign server`: generate the key and CSR on the server (`openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout api.key -out api.csr -subj "/CN=api.home"`), sign it with the SANs the server answers to (`sign server api.home --csr api.csr --san api.home --out api.crt`), and point `ssl_certificate` at the returned certificate and `ssl_certificate_key` at the key that never left the server. Re-signing a server revokes its previous certificate at once, as `create server` does, and clients that check the CRL reject the old one from then on, so install the new certificate promptly.

### Rotating a client certificate

A plain `create client alice` revokes the old certificate at once, which cuts the device off until the new bundle is installed. For routine renewal, keep the old one live until the device has switched:

```bash
tiny-pki --store ./stores/ca create client alice --keep-previous   # prints the previous serial
tiny-pki --store ./stores/ca export p12 alice                      # the newer certificate
# install the bundle on the device, then:
tiny-pki --store ./stores/ca revoke 0x<previous-serial>
```

Until the old serial is revoked, `list clients` marks it superseded, `check` reports it as `alice (superseded, 0x<serial>)`, and `revoke alice` is refused in favour of `revoke 0x<serial>`.

### A lost device or a compromised key

Revoke at once, reload the TLS server, and issue a replacement if needed:

```bash
tiny-pki --store ./stores/ca revoke alice
sudo systemctl reload nginx
tiny-pki --store ./stores/ca create client alice
```

### Serving mTLS from nginx

Point nginx at the key-free copies in `public/`:

```nginx
ssl_client_certificate /srv/pki/home-ca/public/ca.crt;
ssl_verify_client      on;
ssl_crl                /srv/pki/home-ca/public/crl.pem;
```

Grant or bind-mount the `public/` directory rather than individual files, so the server sees each new CRL; [store.md](store.md#public-for-tls-servers) has a sandboxed systemd example. Match client identities against the whole `$ssl_client_s_dn` string (see the nginx `map` in [api.md](api.md#issue)).

### Stapling OCSP from nginx

For clients that check a server certificate's revocation through OCSP, publish stapling responses once and point each server block at its file:

```bash
tiny-pki --store /srv/pki/home-ca ocsp
```

```nginx
ssl_stapling        on;
ssl_stapling_file   /srv/pki/home-ca/public/ocsp/api.home.der;
```

nginx reads the file at startup and reload, so reload it after each publish, as for the CRL. The [CRL timer](#renewing-the-crl-on-a-timer) refreshes the responses too; run it daily, since they are valid for 7 days (`ocsp --days N` changes that).

### Renewing the CRL on a timer

nginx rejects every client once the CRL passes its `nextUpdate` (7 days after each publish by default), so publish a fresh one daily and reload the server. With `crl hook 'systemctl reload nginx'` set, the publish runs the reload itself, and so does every `revoke`. `/etc/systemd/system/tiny-pki-crl.service`:

```ini
[Unit]
Description=Publish a fresh tiny-pki CRL

[Service]
Type=oneshot
ExecStart=/usr/local/bin/tiny-pki --store /srv/pki/home-ca --color never crl
```

`/etc/systemd/system/tiny-pki-crl.timer`:

```ini
[Unit]
Description=Daily tiny-pki CRL publish

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

Enable it with `systemctl enable --now tiny-pki-crl.timer`. Without a hook, add `ExecStartPost=/usr/bin/systemctl reload nginx` to the service. The same run refreshes [stapled OCSP responses](#stapling-ocsp-from-nginx), which are also valid for 7 days. Pair it with a `check --crl-renewal 1d` timer ([monitoring.md](monitoring.md#systemd-timer)), which reports the CRL as expiring if the publish stops working or if `crl --days` is set too short for a daily run. For a weekly timer, set `crl --days 30` (and `--crl-renewal 7d`).

### Running an intermediate CA

A root that signs only intermediates can stay offline: its key is needed only to sign or renew an intermediate and to re-sign its CRL. The intermediate store does the day-to-day issuing and revoking.

```bash
# On the offline host (or an encrypted store you only unlock for this):
tiny-pki --store /media/usb/root init --cn "Home Root" --path-length 1 --permit home --permit 192.168.0.0/16 \
  --encrypt-key --crl-days 180
tiny-pki --store /srv/pki/issuing init --intermediate-of /media/usb/root --cn "Home Issuing"
# From then on, issue and revoke from the intermediate:
tiny-pki --store /srv/pki/issuing create server api.home --san api.home
```

When the intermediate cannot reach the root's store, create its key and CSR where it runs, sign the CSR on the root with `sign intermediate`, and install the result with `CertificateStore.write_ca(cert, key, chain_pem=root_cert)` ([store.md](store.md#using-the-store-from-python)). Then publish its first CRL together with the root's: `tiny-pki --store /srv/pki/issuing crl --chain-crl root-crl.pem`.

Point nginx at the intermediate store's `public/` directory. Clients need the whole chain, and nginx checks the CRL of every CA in it once `ssl_crl` is set, which is why `public/crl.pem` carries the root's CRL as well:

```nginx
ssl_certificate         /etc/nginx/tls/api.home-fullchain.pem;   # servers/api.home-*.crt + public/ca.crt
ssl_client_certificate  /srv/pki/issuing/public/ca-chain.pem;    # the intermediate and the root
ssl_verify_depth        2;
ssl_verify_client       on;
ssl_crl                 /srv/pki/issuing/public/crl.pem;         # the intermediate's CRL and the root's
```

The root's CRL expires like any other, and nginx then rejects every client, so re-sign it on the root well inside its lifetime (`crl --days 180` suits an offline root) and import it on the intermediate host, which republishes `public/crl.pem`:

```bash
tiny-pki --store /media/usb/root crl
tiny-pki --store /srv/pki/issuing crl --chain-crl /media/usb/root/public/crl.pem
```

`check` on the intermediate store reports the root's CRL as `issuer crl Home Root`, so the [check timer](monitoring.md#systemd-timer) warns before it runs out. To retire a compromised intermediate, revoke it on the root (`revoke "Home Issuing"`), then import the root's new CRL wherever the chain is served.
