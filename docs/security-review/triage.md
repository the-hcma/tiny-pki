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
| 1 | CN with `../` accepted by `normalize_subject_attribute`; `export pem`'s default output path uses the raw CN, letting a crafted identity write cert+key outside the intended directory | High | Claude | Fix required | follow-up issue (fix) |
| 2 | `write_ca` / `write_crl` follow a pre-planted symlink at the fixed `ca.key` / `ca.crt` / `crl.pem` paths, and `_write_index` follows one at the adjacent `index.json.tmp` path (unlike leaf cert/key paths, and unlike `index.json` itself, which `rename(2)` replaces rather than follows — all already hardened, or immune, via `_path_under_root` / `os.replace` semantics) | High | Claude | Fix required | follow-up issue (fix) |
| 3 | `tiny_pki.secrets` Fernet derivation has no domain separation; README's own example (Django `SECRET_KEY`) invites reusing an already multi-purpose secret | Medium | Claude | Fix or accept-with-rationale — needs @thehcma decision | follow-up issue |
| 4 | `MIN_PKCS12_PASSWORD_LENGTH = 8` is a low enforced floor for an offline-attackable bundle (docs already recommend long/random) | Low | Claude | Fix or accept — needs @thehcma decision | follow-up issue |
| 5 | REPL history file (`~/.cache/tiny-pki/history`) isn't chmod'd `0600` like every other on-disk artifact this codebase writes | Low | Claude | Fix (small, consistent with existing pattern) | follow-up issue |
| 6 | `dependabot-auto-merge.yml`'s `pull_request_target` is safe today but undocumented; a future edit that adds a head-ref checkout would reintroduce a known attack pattern | Info | Claude | Accept — add a guarding comment | follow-up issue (docs/comment only) |

## Not yet triaged

- **Repo governance audit** (branch protection, Actions allowlist, CODEOWNERS,
  trusted-publishing config vs. `SECURITY.md`'s claims) — blocked on a GitHub
  API rate limit during the Claude pass; needs a follow-up run.
- **Second-vendor reviewer's findings** — none yet; this table will grow a
  `Reviewer(s)` value of "Claude + <vendor>" or a new row once that report
  exists.

## Closing criteria (from issue #34)

- Every Critical/High finding (rows 1–2 today) fixed with a test, or
  explicitly accepted by @thehcma, before #34 closes.
- Every Medium/Low finding (rows 3–6) either fixed or filed as a tracked
  follow-up issue — this table's "Tracking" column is the source of truth for
  which.
- This table reflects **both** reviewers before #34 closes; today it reflects
  only one.
