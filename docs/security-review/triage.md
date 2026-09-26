# Security review triage

Merges findings across reviewers into one disposition table, per issue #34.

**Status: single-reviewer.** Only the Claude report
([`2026-09-25-claude-review.md`](./2026-09-25-claude-review.md)) exists so far.
The independent second-vendor reviewer (GPT-5.x Codex CLI, or Cursor's Security
Review agent on a non-Claude model — see issue #34) has not run yet. Every row
below is provisional until that report lands and is merged in; do not close
#34 from this table alone.

| # | Finding | Severity | Reviewer(s) | Disposition | Tracking |
| --- | --- | --- | --- | --- | --- |
| 1 | CN with `../` accepted by `normalize_subject_attribute`; `export pem`'s default output path uses the raw CN, letting a crafted identity write cert+key outside the intended directory | High | Claude | **Fixed** — `normalize_subject_attribute` now rejects `/`/`\`; `_cmd_export`'s default filename is also sanitized as defense in depth for a hand-edited `index.json` | the-hcma/tiny-pki#79 |
| 2 | `write_ca` / `write_crl` follow a pre-planted symlink at the fixed `ca.key` / `ca.crt` / `crl.pem` paths, and `_write_index` follows one at the adjacent `index.json.tmp` path (unlike leaf cert/key paths, and unlike `index.json` itself, which `rename(2)` replaces rather than follows — all already hardened, or immune, via `_path_under_root` / `os.replace` semantics) | High | Claude + mergestorm-vortex (agent review, 4 rounds) | **Fixed**, after four review rounds on the same PR (#88) converged on the general form: (1) the fix that merged in #85 only guarded the exact final path component, missed by a symlink at the `ca/` directory itself; (2) the same gap in `_migrate_legacy_layout`'s flat-CA-material move; (3)/(4) checking only the final component (whether via `_open_new_file` originally, or the leaf-only check that replaced it) still missed a symlink at *any* component — leaf or intermediate — whose target happened to stay inside the store root, since `_path_under_root`'s containment check only looks at where the fully-resolved path lands. `_validated_write_path` now walks every component of the unresolved relative path and rejects a symlink at any of them, regardless of where it points, before falling through to `_path_under_root`; used by all four write call sites plus the legacy-migration move | the-hcma/tiny-pki#80 |
| 3 | `tiny_pki.secrets` Fernet derivation has no domain separation; README's own example (Django `SECRET_KEY`) invites reusing an already multi-purpose secret | Medium | Claude | **Fixed** — the Fernet key is now HKDF-SHA256 with a fixed, versioned `info` label (`tiny-pki:fernet-key:v1`), so it is independent of anything else derived from the same secret; `info=None` keeps the legacy `sha256(secret)` path for reading and migrating old tokens. `docs/security.md` states that this does not help if the secret itself leaks | the-hcma/tiny-pki#81, fixed in the-hcma/tiny-pki#91 |
| 4 | `MIN_PKCS12_PASSWORD_LENGTH = 8` is a low enforced floor for an offline-attackable bundle (docs already recommend long/random) | Low | Claude | **Fixed** — `MIN_PKCS12_PASSWORD_LENGTH` raised from 8 to 16, still a hard floor (`TinyPkiError` below it), matching the docs' long-random-password guidance | the-hcma/tiny-pki#82, fixed in the-hcma/tiny-pki#92 |
| 5 | REPL history file (`~/.cache/tiny-pki/history`) isn't chmod'd `0600` like every other on-disk artifact this codebase writes | Low | Claude | **Fixed** — the file is created (or tightened, if pre-existing) with mode `0600` before `FileHistory` ever opens it | the-hcma/tiny-pki#82 |
| 6 | `dependabot-auto-merge.yml`'s `pull_request_target` is safe today but undocumented; a future edit that adds a head-ref checkout would reintroduce a known attack pattern | Info | Claude | **Fixed** — added a guarding comment mirroring `cve-check.yml`'s | the-hcma/tiny-pki#82 |

## Not yet triaged

- **Repo governance audit** (branch protection, Actions allowlist, CODEOWNERS,
  trusted-publishing config vs. `SECURITY.md`'s claims) — done as part of
  writing `SECURITY.md`: every claim there was checked live against the repo's
  GitHub settings. It surfaced one real gap (`allowed_actions: all` rather
  than an explicit allowlist), tracked as the-hcma/tiny-pki#83.
- **Second-vendor reviewer's findings** — none yet; this table will grow a
  `Reviewer(s)` value of "Claude + <vendor>" or a new row once that report
  exists.

## Closing criteria (from issue #34)

- Every Critical/High finding (rows 1–2 today) fixed with a test, or
  explicitly accepted by @thehcma, before #34 closes. Rows 1 and 2 are both
  fixed.
- Every Medium/Low finding (rows 3–6) either fixed or filed as a tracked
  follow-up issue — this table's "Tracking" column is the source of truth for
  which.
- This table reflects **both** reviewers before #34 closes; today it reflects
  only one.
