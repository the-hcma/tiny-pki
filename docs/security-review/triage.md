# Security review triage

Merges findings across reviewers into one disposition table, per issue #34.

**Status: both reviewers in.** Two independent reports exist:

- [`2026-09-25-claude-review.md`](./2026-09-25-claude-review.md) — Claude
  Sonnet 5 via Claude Code, commit `b3bbf01` (rows 1–6).
- [`2026-09-26-grok-review.md`](./2026-09-26-grok-review.md) — Grok 4.7 via a
  Cursor agent subagent, commit `074cfa0` (rows 7–23), with its reproduction
  script in [`2026-09-26-grok-poc/repro.py`](./2026-09-26-grok-poc/repro.py)
  (`uv run python docs/security-review/2026-09-26-grok-poc/repro.py` from the
  repo root; writes only under the system temp dir).

The second review ran on a later commit, after rows 1–6 were fixed, so it did
not re-report them. To keep it independent it ran against a `git archive`
snapshot with no `.git` history and no `docs/security-review/`, and was told not
to read GitHub issues or PRs. OpenAI's GPT-5.6 was tried first and refused the
task under its cybersecurity safety filter, so Grok (xAI) was used instead.

Severities in the table are the triage severity. Where it differs from the
reviewer's, the disposition says why. "Verified" means the finding was
re-reproduced during triage, independently of the reviewer's own script.

| # | Finding | Severity | Reviewer(s) | Disposition | Tracking |
| --- | --- | --- | --- | --- | --- |
| 1 | CN with `../` accepted by `normalize_subject_attribute`; `export pem`'s default output path uses the raw CN, letting a crafted identity write cert+key outside the intended directory | High | Claude | **Fixed** — `normalize_subject_attribute` now rejects `/`/`\`; `_cmd_export`'s default filename is also sanitized as defense in depth for a hand-edited `index.json` | the-hcma/tiny-pki#79 |
| 2 | `write_ca` / `write_crl` follow a pre-planted symlink at the fixed `ca.key` / `ca.crt` / `crl.pem` paths, and `_write_index` follows one at the adjacent `index.json.tmp` path (unlike leaf cert/key paths, and unlike `index.json` itself, which `rename(2)` replaces rather than follows — all already hardened, or immune, via `_path_under_root` / `os.replace` semantics) | High | Claude + mergestorm-vortex (agent review, 4 rounds) | **Fixed**, after four review rounds on the same PR (#88) converged on the general form: (1) the fix that merged in #85 only guarded the exact final path component, missed by a symlink at the `ca/` directory itself; (2) the same gap in `_migrate_legacy_layout`'s flat-CA-material move; (3)/(4) checking only the final component (whether via `_open_new_file` originally, or the leaf-only check that replaced it) still missed a symlink at *any* component — leaf or intermediate — whose target happened to stay inside the store root, since `_path_under_root`'s containment check only looks at where the fully-resolved path lands. `_validated_write_path` now walks every component of the unresolved relative path and rejects a symlink at any of them, regardless of where it points, before falling through to `_path_under_root`; used by all four write call sites plus the legacy-migration move | the-hcma/tiny-pki#80 |
| 3 | `tiny_pki.secrets` Fernet derivation has no domain separation; README's own example (Django `SECRET_KEY`) invites reusing an already multi-purpose secret | Medium | Claude | **Fixed** — the Fernet key is now HKDF-SHA256 with a fixed, versioned `info` label (`tiny-pki:fernet-key:v1`), so it is independent of anything else derived from the same secret; `info=None` keeps the legacy `sha256(secret)` path for reading and migrating old tokens. `docs/security.md` states that this does not help if the secret itself leaks | the-hcma/tiny-pki#81, fixed in the-hcma/tiny-pki#91 |
| 4 | `MIN_PKCS12_PASSWORD_LENGTH = 8` is a low enforced floor for an offline-attackable bundle (docs already recommend long/random) | Low | Claude | **Fixed** — `MIN_PKCS12_PASSWORD_LENGTH` raised from 8 to 16, still a hard floor (`TinyPkiError` below it), matching the docs' long-random-password guidance | the-hcma/tiny-pki#82, fixed in the-hcma/tiny-pki#92 |
| 5 | REPL history file (`~/.cache/tiny-pki/history`) isn't chmod'd `0600` like every other on-disk artifact this codebase writes | Low | Claude | **Fixed** — the file is created (or tightened, if pre-existing) with mode `0600` before `FileHistory` ever opens it | the-hcma/tiny-pki#82 |
| 6 | `dependabot-auto-merge.yml`'s `pull_request_target` is safe today but undocumented; a future edit that adds a head-ref checkout would reintroduce a known attack pattern | Info | Claude | **Fixed** — added a guarding comment mirroring `cve-check.yml`'s | the-hcma/tiny-pki#82 |
| 7 | `export pem` / `export p12 --out` write through a pre-existing symlink at the destination (`_write_secret_file` opens with `O_CREAT\|O_TRUNC`, no `O_NOFOLLOW`), so a planted link in the export directory receives the leaf private key | High | Grok | **Done** — verified: a symlink at `./alice.pem` got the full cert + key PEM. Exports now go through `write_file_atomic` (refuse an existing symlink, `O_EXCL` temp file, `os.replace`) in the-hcma/tiny-pki#106 | the-hcma/tiny-pki#96 (under #78) |
| 8 | A CA with only IP permitted subtrees leaves DNS SANs unconstrained (RFC 5280 semantics), and non-interactive `create server` auto-adds the CN as a DNS SAN, so an IP-only CA issues e.g. `google.com` that OpenSSL accepts; `docs/security.md` overstates what `permitted_subtrees` guarantees | Medium | Grok | **Open** — verified with `openssl verify` | the-hcma/tiny-pki#97 (under #78) |
| 9 | A restored older (still unexpired) CRL silently un-revokes certificates: `check` trusts the CRL bytes over `index.json`, exits 0, and `--include-revoked` reports the revoked leaf as `ok`; `check_certificate` also treats a CRL past `nextUpdate` as proof of non-revocation | Medium | Grok | **Open** — verified: after rollback, `openssl verify -crl_check` accepts the revoked leaf and `tiny-pki check --within 0` exits 0 | the-hcma/tiny-pki#98 (under #78) |
| 10 | `get_certificate` matches a needle against CN **or** serial, first live match wins; a CN equal to another cert's serial makes lookups ambiguous | Low (reviewer: Medium) | Grok | **Open** — verified, but downgraded: `revoke <serial>` correctly revokes the cert with that serial; the actual hazard is the reverse (looking up the cert *named* like a serial hits the other one), and it needs a deliberately chosen 40-hex-char CN. Fix: prefer an exact serial match, refuse CN/serial ambiguity | the-hcma/tiny-pki#100 (under #78) |
| 11 | `delete --force` on an active cert removes it from the index without tombstoning it, so the regenerated CRL omits the serial and exported copies stay valid | Low | Grok | **Open** — verified: exported cert still passes `openssl verify -crl_check` after `delete --force` | the-hcma/tiny-pki#100 (under #78) |
| 12 | Leaf (`add_certificate`) and bundle (`write_bundle`) writes follow a symlink whose target stays inside the store, so they can overwrite `ca/ca.key` | Low | Grok (variant of row 2) | **Open** — reproduced by the reviewer's script. Row 2's `_validated_write_path` covers CA/CRL/index writes but was never applied to leaf/bundle paths; exploitable only when someone else can write inside the store (row 13) | the-hcma/tiny-pki#99 (under #78) |
| 13 | Store directories and `index.json` / `crl.pem` / `ca.crt` take the process umask (mode `0777` under umask `000`); only secrets get an explicit `0600` | Low | Grok | **Open** — reproduced by the reviewer's script. Enables rows 9, 12, and 14 on a shared host | the-hcma/tiny-pki#99 (under #78) |
| 14 | `index.json` `key_path` / `cert_path` only need to stay under the store root, so `key_path: "ca/ca.key"` makes `export` ship the CA key as the leaf key | Low | Grok | **Open** — reproduced by the reviewer's script. Restrict paths to `clients/` / `servers/` / `bundles/` | the-hcma/tiny-pki#99 (under #78) |
| 15 | `--permit .example.com` has its leading dot stripped, silently permitting the apex (OpenSSL syntax means subdomains only) | Low | Grok | **Open** | the-hcma/tiny-pki#101 (under #78) |
| 16 | An excluded IPv4 range does not cover the IPv4-mapped IPv6 form (`::ffff:10.1.2.3`) | Low | Grok | **Open** — matches a literal reading of RFC 5280; matters only for clients that normalize mapped addresses | the-hcma/tiny-pki#101 (under #78) |
| 17 | The CLI never persists `crlNumber` (default is microseconds since the epoch), so a backward clock step can publish a lower number than the previous CRL | Low | Grok | **Open** — reasoning only | the-hcma/tiny-pki#102 (under #78) |
| 18 | `ca.key`, leaf keys, and `crl.pem` are written in place with `O_TRUNC` (no temp file + `fsync` + `rename`), so a crash mid-write can leave a truncated key or CRL | Low | Grok | **Open** — reasoning only | the-hcma/tiny-pki#102 (under #78) |
| 19 | `TINY_PKI_GIT_SHA` is printed by `--version` without a hex check (newlines / escapes pass through) | Low | Grok | **Open** | the-hcma/tiny-pki#103 (under #78) |
| 20 | Library `validity_days` has no upper bound, so huge values raise `OverflowError` instead of `TinyPkiError` (the CLI caps `--days`) | Low | Grok | **Open** | the-hcma/tiny-pki#103 (under #78) |
| 21 | CI installs `uv` with `version: latest` and `pip-audit` unpinned (in the `issues: write` CVE job); Dependabot auto-merge includes `cryptography` bumps | Low | Grok | **Open** — needs a decision on pinning cadence and on auto-merging `cryptography` | the-hcma/tiny-pki#104 (under #78) |
| 22 | Docs caveats: README library snippet sets no `permitted_subtrees`; README says `cryptography` ≥ 43.0.1 while `pyproject.toml` requires ≥ 50.0.1; the nginx `check` recipe has no CRL input; name constraints do not cover client CNs | Info | Grok | **Open** | the-hcma/tiny-pki#105 (under #78) |
| 23 | No trusted-publishing workflow yet; PKCS#12 KDF rounds are `cryptography` defaults (PBKDF2 20000 iterations) | Info | Grok | **Accepted / deferred** — publishing is tracked by #11; the KDF defaults are fine for the enforced 16-byte random passwords | the-hcma/tiny-pki#11 |

## Not yet triaged

- **Repo governance audit** (branch protection, Actions allowlist, CODEOWNERS,
  trusted-publishing config vs. `SECURITY.md`'s claims) — done as part of
  writing `SECURITY.md`: every claim there was checked live against the repo's
  GitHub settings. It surfaced one real gap (`allowed_actions: all` rather
  than an explicit allowlist), now **fixed**: the repo is on
  `allowed_actions: selected` with GitHub-owned actions plus
  `astral-sh/setup-uv` and `nick-fields/retry` allowed, tracked as
  the-hcma/tiny-pki#83 and documented in the-hcma/tiny-pki#93.
- **Second-vendor reviewer's findings** — merged above as rows 7–23. The two
  reports did not overlap on any finding (row 12 is a new variant of row 2's
  bug class that the #88 fix did not reach). The second report's "areas
  reviewed with no findings" independently confirms the fixes for rows 1, 2,
  3, 4, and 5.

## Closing criteria (from issue #34)

- Every Critical/High finding fixed with a test, or explicitly accepted by
  @thehcma, before #34 closes. Rows 1 and 2 are fixed; **row 7 is open** (the-hcma/tiny-pki#96).
- Every Medium/Low finding either fixed or filed as a tracked follow-up issue
  — this table's "Tracking" column is the source of truth for which. Rows 3–6
  are fixed; rows 8–22 are tracked as sub-issues of the-hcma/tiny-pki#78
  (#97–#105).
- This table reflects **both** reviewers.
