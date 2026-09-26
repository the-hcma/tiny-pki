# Monitoring expiry

`tiny-pki check` flags expired, expiring, not-yet-valid, revoked, and untrusted certificates and CRLs. Its exit code follows the Nagios / monitoring-plugin convention, so the same command works from cron, a systemd timer, or a monitoring agent. The library equivalent is described under [Check](api.md#check).

## What gets checked

- `tiny-pki --store DIR check` checks the store's CA certificate, its CRL, and every active leaf. Add `--include-revoked` to list revoked leaves too (they report `revoked`). Leaves are checked against the store's CA and CRL. A CRL that is not signed by the store's CA is reported as `untrusted` and is not used for revocation. `index.json` is authoritative for revocation: a leaf revoked there reports `revoked` even if the CRL omits it, a CRL missing any serial revoked in the index (for example an older CRL restored from backup) reports `untrusted` (shown even when `--kind` leaves out `crl`), and a missing CRL while the index has revocations is an error (exit 3). Once the CRL passes its `nextUpdate`, leaves checked against it report `untrusted` with "revocation status unknown", because an old CRL can predate a revocation; a leaf revoked in the index still carries its "revoked in index.json" reason.
- `tiny-pki check PATH...` checks files instead, and needs no store:
  - PEM or DER certificates, and every certificate in a chain file;
  - CRLs (PEM or DER), whose freshness is their `nextUpdate`;
  - PKCS#12 bundles (`*.p12`, `*.pfx`), opened with `--password-file PATH` (first line of the file; never pass the password as an argument);
  - directories, scanned one level deep for `*.pem`, `*.crt`, `*.cer`, `*.crl`, `*.p12`, and `*.pfx`. Files that cannot be checked (such as private keys, or PKCS#12 bundles without `--password-file` or with the wrong password) are skipped with a note on stderr and do not change the exit code. If a directory must not be skipped silently, list its files explicitly.
- `--ca PATH` (file targets only) also flags certificates and CRLs not directly issued by that CA as `untrusted`.
- `--crl PATH` (file targets only; requires `--ca`) checks certificates against that CRL (PEM or DER, signed by `--ca`): a listed serial reports `revoked`, and a CRL past its `nextUpdate` makes certificates `untrusted` (revocation status unknown). Without `--crl`, file checks cover expiry and issuer only, never revocation.
- `--kind ca|client|server|crl` restricts the results; repeat it to select several kinds.

## Alert window

A result is `expiring` when it is valid now but its `notAfter` (or the CRL's `nextUpdate`) falls on or before the cutoff:

| Flag | Cutoff |
| --- | --- |
| `--within DAYS` | now + DAYS |
| `--by YYYY-MM-DD` | the end of that day, local time |
| both | whichever is earlier |
| neither | now + a third of each certificate's own lifetime, capped at 30 days for leaves and 180 days for the CA; CRLs are not capped (10 days for the default 30-day CRL) |

When a leaf is checked against its CA and the CA expires first, the CA's expiry is used, with the reason "CA expires first".

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | everything is `ok` |
| 1 | at least one result is `expiring` (and nothing worse) |
| 2 | at least one result is `expired`, `not_yet_valid`, `revoked`, or `untrusted` |
| 3 | the check could not run: bad arguments, missing store, or an explicitly listed file that is unreadable, not a certificate, or a PKCS#12 bundle that will not open (entries found by scanning a directory are skipped instead) |

## Output

The default output is a table sorted by expiry (soonest first), followed by a summary line:

```text
status        kind    name      expires           remaining
expiring      crl     crl       2026-10-25 09:43  29 days
expiring      server  api.home  2026-12-24 08:38  89 days
ok            ca      ca        2036-09-22 09:38  3649 days
check: 2 expiring, 1 ok; within 100 days
```

`--quiet` prints only the problem rows plus the summary, and prints nothing at all when everything is `ok`. That makes it a good fit for cron, which mails any output.

`--json` prints one object:

```json
{
  "status": "expiring",
  "results": [
    {
      "name": "api.home",
      "kind": "server",
      "status": "expiring",
      "subject": "api.home",
      "issuer": "Docs CA",
      "serial_number": "77dd2ebacfd1245af76ad561daaf9a4af60905f6",
      "not_before": "2026-09-25T13:38:29+00:00",
      "not_after": "2026-12-24T13:38:29+00:00",
      "cutoff": "2027-01-03T13:43:29.747722+00:00",
      "days_remaining": 89,
      "reasons": ["expires on 2026-12-24T13:38:29+00:00, before the cutoff 2027-01-03T13:43:29.747722+00:00"]
    }
  ]
}
```

| Field | Meaning |
| --- | --- |
| `status` (top level) | the most severe result status |
| `name` | store identity (`ca`, `crl`, or the leaf name) or file path; chain entries are `PATH #N` |
| `kind` | `ca`, `client`, `server`, `crl`, or `unknown` |
| `status` | `ok`, `expiring`, `not_yet_valid`, `expired`, `revoked`, or `untrusted` |
| `subject`, `issuer` | common name, or the full RFC 4514 name when there is no CN |
| `serial_number` | lowercase hex; the CRL number for CRLs; `null` if absent |
| `not_before`, `not_after`, `cutoff` | ISO 8601 in UTC; `not_after` is `null` for a CRL without `nextUpdate` |
| `days_remaining` | whole days until `not_after`, negative once expired; `null` without `not_after` |
| `reasons` | human-readable explanations, including informational notes |

Timestamps in JSON are UTC; the table shows local time.

## Recipes

### cron

Mail only when something needs attention (cron mails any output):

```cron
0 8 * * * tiny-pki --store /srv/pki --color never check --quiet
```

### systemd timer

`/etc/systemd/system/tiny-pki-check.service`:

```ini
[Unit]
Description=Check tiny-pki certificates for expiry

[Service]
Type=oneshot
ExecStart=/usr/local/bin/tiny-pki --store /srv/pki --color never check --quiet
```

`/etc/systemd/system/tiny-pki-check.timer`:

```ini
[Unit]
Description=Daily tiny-pki expiry check

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

Enable it with `systemctl enable --now tiny-pki-check.timer`. A non-zero exit marks the service as failed, so `systemctl --failed` or an `OnFailure=` unit can raise the alert.

### Nagios, Icinga, and other agents

The exit codes map directly onto plugin states (OK, WARNING, CRITICAL, UNKNOWN), so `tiny-pki --store /srv/pki --color never check --within 30` can be used as a check command as is. The summary is the last line of the output; agents that parse structured output should use `--json` instead.

### jq

List everything that is not `ok`:

```bash
tiny-pki --store /srv/pki check --json | jq -r '.results[] | select(.status != "ok") | "\(.status)\t\(.name)\t\(.not_after)"'
```

Check the certificates nginx serves, against the CA that issued them and its CRL:

```bash
tiny-pki check /etc/nginx/certs --ca /srv/pki/ca/ca.crt --crl /srv/pki/ca/crl.pem --within 14
```

Expiry and revocation are separate questions: drop `--crl` and the same command
still exits 0 for a revoked certificate. Check the CRL nginx loads (`ssl_crl`)
too, so an expired CRL is caught before nginx starts rejecting every client:

```bash
tiny-pki check /srv/pki/ca/crl.pem --ca /srv/pki/ca/ca.crt
```
