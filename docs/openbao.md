# tiny-pki and OpenBao

[OpenBao](https://openbao.org/) (the open-source fork of HashiCorp Vault) ships a [PKI secrets engine](https://openbao.org/docs/secrets/pki/) that overlaps with tiny-pki. This page compares the two, so you can pick one or combine them. The OpenBao column reflects its 2.7 documentation; check the [PKI API reference](https://openbao.org/docs/api/secret/pki/) for anything you rely on.

**We recommend tiny-pki for a self-contained set of applications that you host and maintain yourself**: a home network, a small fleet of devices, or a handful of services where one operator owns the CA, the servers and the clients. For anything larger, or for certificates that must be issued automatically to machines you don't manage, use OpenBao.

One difference often decides the choice on its own: **tiny-pki has no HSM support.** Signing always needs the CA private key as PEM bytes in memory: the CLI store keeps it in a file (optionally encrypted at rest) and decrypts it to sign, and library callers pass it in from wherever they store it. OpenBao can keep issuer keys in an HSM or a cloud KMS through [external keys](https://openbao.org/docs/api/system/external-keys/) and the PKCS#11 KMS plugin from openbao-plugins, so the key never exists outside the device. If your policy requires hardware-backed CA keys, use OpenBao, or at least put the online intermediate there ([combining them](#combining-them-a-tiny-pki-root-over-an-openbao-intermediate)).

## Comparison

| Area | tiny-pki | OpenBao PKI engine |
| --- | --- | --- |
| How it runs | Python library and CLI; nothing runs in the background | A server that must be running and unsealed, with a full HTTP API |
| CA layout | One CA per store: a root (`--path-length 0` or `1`) or an intermediate with its chain in `public/ca-chain.pem`; a root can sign an intermediate whose key lives elsewhere | Root and intermediate CAs, several issuers per mount with per-issuer usage restrictions, cross-signing, imported keys, issuer rotation |
| Issuance | Generates a key and certificate, or signs a CSR (client, server, intermediate) under a fixed built-in profile; client certificates can carry one URI SAN such as a SPIFFE ID | Issues certificates or signs CSRs under roles (allowed domains, TTLs, key types), or under CEL policies for dynamic rules |
| Policy | DNS, IP and URI Name Constraints (narrowable on intermediates), validity caps, DN character checks; for a CSR, the CA sets the name and extensions | Role constraints and ACL policies across many auth methods; DNS Name Constraints (`permitted_dns_domains`) on root and intermediate generation |
| Revocation | Full CRL (7 days by default, chain CRLs included for an intermediate), optional CRL Distribution Points, pre-signed OCSP responses for stapling, and `respond_ocsp` for a consumer's own responder; renewal on an external timer with a publish hook to reload the server | CRLs with optional delta CRLs and automatic rebuilds, a built-in OCSP responder, cross-cluster unified CRLs, automatic tidy of expired certificates |
| Automation | None; the caller invokes it, and the publish hook can reload nginx or Mosquitto | ACME server for certbot, Caddy, nginx and cert-manager (certificates capped at 90 days), plus the HTTP API |
| Key protection | No HSM support: signing needs the CA key in memory; the CLI store keeps it as a mode-`0600` file, optionally encrypted with a secret (`init --encrypt-key`), and library callers store it themselves; with CSR signing, leaf and intermediate keys never reach the CA | Keys protected by the seal; issuer keys can live in an HSM or KMS through external keys (the PKCS#11 KMS plugin from openbao-plugins) |
| Storage and availability | Plain files (`index.json`, PEMs), or the consumer's own database when used as a library | Integrated Raft storage, clustering, snapshots |
| Audit | None beyond the files and your own version control | Audit devices (file, syslog, socket) logging API requests and responses |
| Extras | PKCS#12 export (legacy format and full chains), split PEM export for `certfile` / `keyfile` / `cafile` setups, `tiny_pki.tls` mutual TLS contexts from PEM bytes, PEM-or-DER inspection with peer identity, `check` with expiry exit codes, a REPL | Issuer-level usage restrictions, `no_store` for high-volume ephemeral certificates |

## Where each fits

tiny-pki is the recommended choice for self-contained, self-hosted and self-maintained applications. It is sized for a household or small-application CA, as in [my-tracks](https://github.com/the-hcma/my-tracks) and [home-warden](https://github.com/the-hcma/home-warden): issue certificates to a handful of devices and servers, publish a CRL or stapled OCSP responses for nginx or Mosquitto, and have no server to unseal, patch or back up. The root can stay offline behind a tiny-pki intermediate, and device keys can stay on the device.

OpenBao is worth its operational cost when many machines or services need certificates automatically, certificates are short-lived and renewed constantly (ACME or the API), several teams need their own permissions, CA keys must live in an HSM or KMS, or you need an audit log, an online OCSP responder or high availability.

## Combining them: a tiny-pki root over an OpenBao intermediate

The two meet at the intermediate CA. tiny-pki keeps the root offline, and OpenBao runs the online intermediate that issues leaves over ACME or its API. The intermediate's key is generated inside OpenBao and never leaves it, and can be HSM-backed there; tiny-pki only sees its CSR. The root's key stays a tiny-pki file, so keep that store offline and encrypted.

1. Create a root that may sign intermediates, on an offline host or in an encrypted store you only unlock for signing:

   ```bash
   tiny-pki --store /media/usb/root init --cn "Home Root" --path-length 1 --permit svc.home --encrypt-key --crl-days 180
   ```

2. Generate the intermediate's key and CSR in OpenBao. For an HSM- or KMS-backed key, use `pki_int/intermediate/generate/kms` with `external_key_ref` instead of `generate/internal`:

   ```bash
   bao secrets enable -path=pki_int pki
   bao write -field=csr pki_int/intermediate/generate/internal common_name="OpenBao Issuing" > bao.csr
   ```

3. Sign it on the root ([`sign intermediate`](cli.md#sign)). `--permit` narrows the intermediate's Name Constraints within the root's:

   ```bash
   tiny-pki --store /media/usb/root sign intermediate "OpenBao Issuing" --csr bao.csr --permit svc.home --out bao.crt
   ```

4. Install the certificate and its chain in OpenBao:

   ```bash
   cat bao.crt /media/usb/root/public/ca.crt > bao-chain.pem
   bao write pki_int/intermediate/set-signed certificate=@bao-chain.pem
   ```

Then configure OpenBao roles, its URLs (`pki_int/config/urls`) and ACME as its documentation describes, keeping role `allowed_domains` inside the root's Name Constraints. The intermediate has path length 0, so OpenBao cannot create further CAs under it.

Relying parties that check revocation check every CA in the chain, so keep the root's CRL fresh and reachable: re-sign it on the root (`tiny-pki crl`) well inside its lifetime and publish it wherever the chain is served. To retire the OpenBao intermediate, revoke it on the root (`revoke "OpenBao Issuing"`) and publish the new root CRL. Renewing the intermediate with `sign intermediate` does not revoke the previous one, whose leaves still chain to it.

## Deliberate non-goals

tiny-pki stays a bytes-in, bytes-out library and a one-shot CLI. These OpenBao features are out of scope on purpose:

- **ACME endpoint and HTTP API.** Both need a long-running network service: ACME requests are unauthenticated by default, and API issuance needs an authentication and token system tiny-pki doesn't have. When you need either, run OpenBao as the intermediate above.
- **Delta CRLs.** OpenSSL enforces a delta CRL only when the verifier sets `X509_V_FLAG_USE_DELTAS`, which nginx, Mosquitto and Python's `ssl` do not, so a delta would silently fail to revoke there. A short full CRL gives the same freshness ([security.md](security.md#revocation-only-works-if-the-crl-is-fresh)).
- **A built-in OCSP responder.** tiny-pki pre-signs responses for stapling, and `respond_ocsp` answers requests for a consumer that runs its own responder; responses are signed with the CA key, so an online responder keeps that key online.
- **Roles, ACL policies and authentication.** Deciding who gets a certificate is the consuming application's job ([security.md](security.md#out-of-scope)).
- **Audit logging, clustering and replicated storage.** The CLI store is a directory, and library callers keep the PEMs in their own database.
