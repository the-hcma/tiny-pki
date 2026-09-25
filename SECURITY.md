# Security policy

tiny-pki mints private CA, server, and client certificates and CRLs used for
mTLS. A CA minted by this library gets installed device-wide on relying
parties (phones, browsers, TLS servers); a bug here is a trust-anchor
compromise for every consumer, not just this repo. **0.1.0 is not published
to PyPI until [#34](https://github.com/the-hcma/tiny-pki/issues/34) — the
pre-release security review — closes.**

## Reporting a vulnerability

Report privately, not in a public issue or PR:

- **GitHub private vulnerability reporting** — <https://github.com/the-hcma/tiny-pki/security/advisories/new>
  (Security tab → Report a vulnerability). Already enabled on this repo.

Include the output of `tiny-pki --version`, the platform, and the smallest
reproduction you have (a code snippet or CLI transcript, never a real CA key
or PKCS#12 password). You will get an acknowledgement within **3 business
days**.

Please do not open a normal issue, post a PR, or disclose publicly until a fix
is released or **90 days** have passed, whichever comes first.

## Supported versions

tiny-pki ships from `main` only. Fixes go into the next release; there are no
back-port branches.

| Version | Supported |
|---------|-----------|
| Latest PyPI release | yes |
| Anything older | no — upgrade to the latest release |

Before the first PyPI release (tracked by
[#11](https://github.com/the-hcma/tiny-pki/issues/11)), "supported" means the
tip of `main`.

## Response targets by severity

| Severity | Meaning here | Triage | Fix released |
|----------|--------------|--------|---------------|
| Critical | CA private-key exposure, a forged or mis-scoped certificate (wrong CN/SAN/EKU/Name Constraints accepted), CRL bypass, RCE | 3 business days | 7 days |
| High | Path traversal / arbitrary file write or read via the store or CLI, secret leaked to logs/history/argv, a validation bypass that produces a certificate a relying party would trust when it shouldn't | 5 business days | 30 days |
| Medium / Low | Everything else that's a real security weakness but needs a specific precondition (e.g. local write access to the store directory) to matter | 10 business days | next routine release |

A fix lands as a normal Conventional-Commit `fix:` PR through the usual
[`gh stack`](.agents/rules/stacking-tool.md) flow and
[agent review loop](.agents/rules/pr-ship-and-review.md).

## What is in scope

- The library (`tiny_pki.*` under `src/tiny_pki/`): certificate/CRL issuance,
  name/SAN validation, the optional `tiny_pki.secrets` Fernet helpers, and
  PKCS#12 bundling.
- The CLI (`tiny_pki.cli.*`, the `tiny-pki` console script and REPL).
- The filesystem store (`tiny_pki.store`) — layout, `index.json` handling,
  legacy-layout migration, file permissions.
- The release pipeline (`.github/workflows/*`, `.github/ci/*`, and — once
  [#11](https://github.com/the-hcma/tiny-pki/issues/11) lands — PyPI trusted
  publishing).

## What is out of scope

- **Consumer applications** built on tiny-pki (e.g.
  [my-tracks](https://github.com/the-hcma/my-tracks),
  [home-warden](https://github.com/the-hcma/home-warden)): how they store
  keys in a database, wire nginx/Mosquitto, manage a Django `SECRET_KEY`, or
  authenticate/authorize who gets a certificate. See the README's
  ["What stays in your app"](README.md#what-stays-in-your-app) section for the
  exact boundary.
- **Host compromise** of a machine that already holds `ca.key` (or a CLI
  store directory in general) — tiny-pki protects the key at rest with file
  permissions ([`docs/security.md`](docs/security.md)), not against a fully
  compromised host or a malicious co-tenant with local shell access to the
  store's filesystem before it's created (see the CA-key/CRL/index symlink
  finding in
  [`docs/security-review/2026-09-25-claude-review.md`](docs/security-review/2026-09-25-claude-review.md)
  for the one case that *is* in scope: symlink-following on writes, tracked
  as a fix, not accepted as out of scope).
- tiny-pki does not authenticate who asks for a certificate, rate-limit
  issuance, or audit-log operations — see
  [`docs/security.md`](docs/security.md#out-of-scope).

## Controls in place

| Control | Where | Gate |
|---------|-------|------|
| Code review | required PR review from the code owner ([`.github/CODEOWNERS`](.github/CODEOWNERS): `* @thehcma`); `required_approving_review_count` is 0 on branch protection because the code owner *is* the approver on a solo-maintained repo, matching this org's usual pattern for single-maintainer repos | required by branch protection |
| Pre-release security review | two independent model/agent stacks review the full repo before 0.1.0 ships ([#34](https://github.com/the-hcma/tiny-pki/issues/34)); raw reports + a merged triage table live under [`docs/security-review/`](docs/security-review/) | blocks [#11](https://github.com/the-hcma/tiny-pki/issues/11) until closed |
| Static analysis | `ruff` + `pyright --strict` via [`.github/ci/python-static`](.github/ci/python-static) (`[tool.ruff]` / `[tool.pyright]` in [`pyproject.toml`](pyproject.toml)) | **required check `Python lint & format checks`** |
| Tests | `pytest` (hermetic) via [`.github/ci/pytest-hermetic`](.github/ci/pytest-hermetic), plus a separate job pinned to the oldest supported Python + oldest allowed `cryptography` ([`.github/ci/pytest-cryptography-minimum`](.github/ci/pytest-cryptography-minimum)) | **required check `Pytest (hermetic)`**; the minimum-version job runs in CI but is not (yet) a required status check |
| Packaging smoke test | builds the wheel/sdist, checks `py.typed` ships, verifies the plain install pulls in only `cryptography` (+ its native deps) and the CLI fails with an install hint without the `[cli]` extra ([`.github/ci/packaging`](.github/ci/packaging)) | runs in CI on every PR |
| Secret scanning (GitHub-native) | secret scanning + **push protection** enabled on `the-hcma/tiny-pki` (Settings → Code security) | blocks a recognized secret from being pushed |
| Secret scanning (CI) | `gitleaks` via [`.github/ci/secret-scan`](.github/ci/secret-scan), pinned version + checksum-verified download, every PR + push | runs every PR; advisory (not a required status check) |
| Dependency CVE scan | `pip-audit --skip-editable` via [`.github/workflows/cve-check.yml`](.github/workflows/cve-check.yml), daily + on demand; files/updates a `security/cve` issue | advisory |
| Dependency alerts | GitHub **Dependabot security updates** enabled | alerts + auto-fix PRs |
| Dependency updates | Dependabot ([`.github/dependabot.yml`](.github/dependabot.yml), weekly, 10-day cooldown, pip + github-actions ecosystems) + auto-merge ([`.github/workflows/dependabot-auto-merge.yml`](.github/workflows/dependabot-auto-merge.yml)) once required checks pass | opens PRs; auto-merges |
| Vulnerability intake | **Private vulnerability reporting** enabled — [report an advisory](https://github.com/the-hcma/tiny-pki/security/advisories/new) | private channel, no public disclosure |
| Actions supply chain | every `uses:` in every workflow is SHA-pinned with a `# vX.Y.Z` comment, and the repo has **`sha_pinning_required`** turned on (any unpinned action fails); default workflow token is **read-only** and **cannot approve pull requests**. Actions are currently allowed from **any** source (`allowed_actions: all`) rather than an explicit allowlist — see [Known gap](#known-gap-actions-allowlist) below | SHA pinning enforced repo-wide; token scope enforced by GitHub |
| Branch protection | required status checks (`Python lint & format checks`, `Pytest (hermetic)`, strict/up-to-date), code-owner review required, force-pushes and branch deletion disallowed on `main` | blocks merge |
| PyPI trusted publishing | not yet wired — tracked by [#11](https://github.com/the-hcma/tiny-pki/issues/11); when it lands, this table gets a row for the publish environment and its approval gate | n/a until #11 |

### Known gap: Actions allowlist

Unlike some sibling repos in this org, `the-hcma/tiny-pki`'s Actions
permissions are set to **`allowed_actions: all`**, not a `selected`
allowlist of trusted publishers. Because `sha_pinning_required` is enabled,
every action actually referenced in a workflow must still be pinned to an
exact commit SHA — a floating tag can't be substituted — but that's a
different guarantee than restricting *which* repositories a SHA can be
pinned from in the first place. This is a real gap relative to the
allowlist model, not something this document is pretending is closed;
tightening it (or documenting why `all` is an accepted tradeoff for this
repo) is filed as a follow-up from
[#34](https://github.com/the-hcma/tiny-pki/issues/34).

## Governance tooling

Compliance and workflow tooling is **not vendored into this repo** — it comes
from [`the-hcma/repository-helpers`](https://github.com/the-hcma/repository-helpers)
and is re-synced per `AGENTS.md`:

| Tool | Purpose |
|------|---------|
| [`github-repo-lint`](https://github.com/the-hcma/repository-helpers/blob/main/scripts/github-repo-lint) | Enforces the org repo-practice contract: branch-protection shape, required workflows, CODEOWNERS, Dependabot cooldown, and that [`.agents/rules/*.md`](.agents/rules) match the canonical templates |
| [`pre-pr-checks`](https://github.com/the-hcma/repository-helpers/blob/main/scripts/dev/pre-pr-checks) | Local pre-submit gate: lint/format, tests, secret-scan, verified-commits |
| [`wait-for-agent-review`](https://github.com/the-hcma/repository-helpers/blob/main/scripts/wait-for-agent-review) | Drives the agent-review loop (reply-before-resolve, CI wait, operator notification) required on every PR |
| [`start-development`](https://github.com/the-hcma/repository-helpers/blob/main/scripts/dev/start-development) | Worktree-per-stack setup at session start |

See [`AGENTS.md`](AGENTS.md) for the full toolchain and review model.

## Reconciling with `docs/security.md`

[`docs/security.md`](docs/security.md) is the *operational* guidance (what to
do with a CA key, how to size validity, how to handle PKCS#12 passwords). This
file is the *process* policy (how to report a vulnerability, what's in scope,
what CI enforces). Where they overlap — e.g. "the CA private key is the whole
trust boundary" — they should say the same thing; if you find a
contradiction, that's itself worth a private report or an issue.
