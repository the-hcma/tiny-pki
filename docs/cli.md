# Command-line reference

`tiny-pki` runs one command and exits, or, with no command, opens a REPL that accepts the same commands. Install it with the `cli` extra (`pipx install 'tiny-pki[cli]'` or `uv tool install 'tiny-pki[cli]'`).

```text
tiny-pki [--store DIR] [--color auto|always|never] [--edit-mode vim|emacs] [COMMAND [ARGS...]]
```

`help` lists the commands and `help COMMAND` prints one command's usage and flags; both work in the REPL and as one-shot commands. The files a store holds are described in [store.md](store.md), and the defaults behind each flag in [defaults.md](defaults.md).

- [Global options](#global-options)
- [Identities](#identities)
- [Exit status](#exit-status)
- Commands: [init](#init), [create](#create), [sign](#sign), [list](#list), [show](#show), [inspect](#inspect), [export](#export), [revoke](#revoke), [delete](#delete), [crl](#crl), [encrypt-key](#encrypt-key), [decrypt-key](#decrypt-key), [check](#check), [completion](#completion), [REPL commands](#repl-commands)
- Workflows: [enrolling a device from a CSR](#enrolling-a-device-from-a-csr), [rotating a client certificate](#rotating-a-client-certificate), [a lost device or compromised key](#a-lost-device-or-a-compromised-key), [serving mTLS from nginx](#serving-mtls-from-nginx), [renewing the CRL on a timer](#renewing-the-crl-on-a-timer)

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

| Flag | Meaning |
| --- | --- |
| `--cn NAME` | CA common name (default `Private CA`). |
| `--org NAME` | Organization (O); leaves inherit it (default `tiny-pki`). |
| `--days N` | CA validity in days (default 3650). Leaves may not outlive the CA. |
| `--key-type rsa\|ec-p256` | Key algorithm (default `rsa`). See [security.md](security.md#key-types-sizes-and-validity). |
| `--key-size 2048\|3072\|4096` | RSA key size (default 4096). Refused with `--key-type ec-p256`. |
| `--permit NAME` | Add a Name Constraint: a DNS suffix (`home` covers `home` and every name under it) or an IP network (`192.168.0.0/16`). Repeat it for each; constrain both DNS and IP (see [security.md](security.md#limit-what-the-ca-can-vouch-for)). Constraints cannot be changed later. |
| `--crl-days N` | CRL lifetime in days, 1–365 (default 30), saved in the store and used by every later publish. |
| `--encrypt-key` | Encrypt `ca/ca.key` at rest when creating the CA; the secret is read from `--key-secret-file`, a configured credential file, or an interactive prompt. |
| `--key-secret-file PATH` | Read the high-entropy CA-key secret from the first line of this file; use only with `--encrypt-key` for `init`. |

```bash
tiny-pki --store ./stores/ca init --cn "Home CA" --permit home --permit 192.168.0.0/16
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
| `--san NAME` | Servers only: a DNS name or IP address. Repeat it for each; without it the CN is the only SAN. |
| `--yes` | Servers only: add a host-like CN that is missing from `--san` without asking. |
| `--no-cn-san` | Servers only: never add the CN to the SANs (needs `--san`). |

TLS clients ignore the CN, so when a server's CN is a host name or IP address missing from `--san`, `create` asks whether to add it. `--yes` and a non-interactive stdin add it, and `--no-cn-san` leaves it out.

```bash
tiny-pki --store ./stores/ca create client alice --days 730
tiny-pki --store ./stores/ca create client phone --key-type ec-p256
tiny-pki --store ./stores/ca create server api.home --san api.home --san 192.168.1.10
```

### sign

```text
tiny-pki --store DIR sign client NAME --csr PATH [options]
```

Issues a client certificate for a certificate signing request (CSR) that a device generated, so its private key never leaves the device: a laptop keychain, a TPM, or a YubiKey. The store records the certificate with no key file. Only the CSR's public key is used. The CN is always `NAME`, and every extension comes from the same client profile `create client` uses; a different CN or any extensions the CSR requests are ignored with a warning. The CSR (PEM, including Windows `certreq`'s `NEW CERTIFICATE REQUEST` header, or DER) must have a valid signature using SHA-256 or stronger, and an RSA 2048/3072/4096 key with public exponent 65537 or an ECDSA P-256 key. Re-signing a name that has a live certificate revokes the old one, as for `create`. See [enrolling a device from a CSR](#enrolling-a-device-from-a-csr).

| Flag | Meaning |
| --- | --- |
| `--csr PATH` | The device's certificate signing request (required). |
| `--days N` | Validity in days (default 397, capped at 825). |
| `--allow-long-validity` | Allow a validity beyond the 825-day cap. |
| `--org NAME` | Organization (O); defaults to the CA's. |
| `--allow-dn-special-chars` | Allow `,` `+` `=` `"` `<` `>` `;` or a leading `#` in the name, as for `create`. |
| `--keep-previous` | Keep the previous certificate live, for [rotation](#rotating-a-client-certificate). |
| `--key-secret-file PATH` | Read the CA-key secret from the first line of a file when the CA key is encrypted. |
| `--out PATH` | Also write the issued certificate (mode `0644`) to this file for the device. |

```bash
tiny-pki --store ./stores/ca inspect laptop.csr        # compare the public key fingerprint with the device
tiny-pki --store ./stores/ca sign client alice-laptop --csr laptop.csr --out alice-laptop.crt
```

### list

```text
tiny-pki --store DIR list [ca|certs|clients|servers|revoked] [--json]
```

With no argument, prints a summary: the CA name and how many clients, servers and revoked certificates the store holds. `clients` and `servers` list live certificates, `revoked` lists revoked ones (including deleted tombstones), `certs` lists everything that still has files, and `ca` shows the CA, its CRL lifetime and the paths TLS servers need. A live certificate that a newer one for the same name replaces is marked "superseded by".

| Flag | Meaning |
| --- | --- |
| `--json` | Print JSON instead; the fields are listed in [store.md](store.md#list---json). |

### show

```text
tiny-pki --store DIR show ca|certs|clients|servers|revoked [--json]
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
```

`pem` writes the certificate and private key to one file (default `NAME.pem` in the current directory). `p12` writes a password-protected PKCS#12 bundle with the certificate, key and CA, for phones and browsers (default `bundles/NAME-SERIAL.p12` in the store). Files are written with mode `0600`, and a destination that is a symlink is refused.

For a certificate issued by [`sign`](#sign), the store has no private key: `pem` writes the certificate alone (mode `0644`), and `p12` is refused.

| Flag | Meaning |
| --- | --- |
| `--out PATH` | Write to this file instead of the default. |
| `--password-file PATH` | `p12`: read the password (at least 16 bytes) from the first line of this file instead of prompting. The CLI then offers to delete the file. |
| `--legacy` | `p12`: use 3DES with a SHA-1 MAC for older Android and Apple keychains that cannot import the default AES-256 bundle. |

The password is never taken as an argument, because arguments end up in shell history and process listings. Without `--password-file`, `export p12` prompts twice.

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
tiny-pki --store DIR crl [--days N] [--key-secret-file PATH]
```

Signs a fresh CRL from the index and writes it to `ca/crl.pem` and `public/crl.pem`. `renew-crl` is an alias. Run it on a timer well inside the CRL lifetime: once the CRL expires, nginx rejects every client (see [renewing the CRL on a timer](#renewing-the-crl-on-a-timer)).

| Flag | Meaning |
| --- | --- |
| `--days N` | Change the stored CRL lifetime (1–365 days) and use it for this and every later publish. |
| `--key-secret-file PATH` | Read the CA-key secret from the first line of a file when the CA key is encrypted. |

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

Flags expired, expiring, not-yet-valid, revoked and untrusted certificates and CRLs, soonest expiry first, and exits with a monitoring-plugin code. Without a path it checks the store's CA, CRL and every live leaf. With paths it checks files instead and needs no store: PEM or DER certificates, chain files, CRLs, PKCS#12 bundles, and directories (one level deep). [monitoring.md](monitoring.md) has the output format, JSON schema and cron / systemd recipes.

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

### Renewing the CRL on a timer

nginx rejects every client once the CRL passes its `nextUpdate`, so publish a fresh one well inside the lifetime and reload the server. `/etc/systemd/system/tiny-pki-crl.service`:

```ini
[Unit]
Description=Publish a fresh tiny-pki CRL

[Service]
Type=oneshot
ExecStart=/usr/local/bin/tiny-pki --store /srv/pki/home-ca --color never crl
ExecStartPost=/usr/bin/systemctl reload nginx
```

`/etc/systemd/system/tiny-pki-crl.timer`:

```ini
[Unit]
Description=Weekly tiny-pki CRL publish

[Timer]
OnCalendar=weekly
Persistent=true

[Install]
WantedBy=timers.target
```

Enable it with `systemctl enable --now tiny-pki-crl.timer`. Pair it with a `check` timer ([monitoring.md](monitoring.md#systemd-timer)), which reports the CRL as expiring if the publish stops working.
