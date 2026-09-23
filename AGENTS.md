# AGENTS.md — Ground Rules for tiny-pki

This file defines the standards for all contributors (human or AI) working on this
codebase. Every change must comply with these rules before it is considered complete.

---

## Project

Python library and CLI for **private CA** crypto: issue CA / server / client
certificates, generate CRLs, export PKCS#12, and inspect PEMs. Built on
`cryptography`. Persistence stays in the consumer (DB, files); the library core
is bytes-in / bytes-out.

- Package import path: `tiny_pki` under `src/`
- Console command: `tiny-pki` (REPL + one-shot commands)
- Consumers: [my-tracks](https://github.com/the-hcma/my-tracks),
  [home-warden](https://github.com/the-hcma/home-warden) (#49)
- Do not commit private keys, live certs, or store directories with real CA material

---

## Session startup

At the **start of every agent session**, before acting from assumed conventions:

1. Read this `AGENTS.md` in full.
2. Read every rule under `.agents/rules/*.md` whose front matter has
   `alwaysApply: true`, plus any rule whose `globs` match files you will touch.
   `AGENTS.md` and the `.agents/rules/` files together are the contract — neither
   alone is complete. `.cursor/rules/*.mdc` files are Cursor injection shims only
   (frontmatter + pointer); do not treat the shim body as the rule.

`CLAUDE.md` (a `@AGENTS.md` import) and `.github/copilot-instructions.md` exist so
Claude Code and Copilot reach this same guidance; do not put rules in them.

Before creating any branch or writing code, initialize the session from the
repository root using [repository-helpers](https://github.com/the-hcma/repository-helpers):

```bash
~/work/ai/repository-helpers/scripts/dev/start-development --refresh
~/work/ai/repository-helpers/scripts/dev/start-development --worktree <stack-name> --no-interactive
```

- **`--refresh`** (first): syncs `main` (marker-aware; this repo is `gh-stack`),
  prunes merged worktrees and branches, pulls latest `main`, then exits.
- **plain / `--worktree`** (second): creates or resumes a worktree under
  `.worktrees/<stack-name>-wt`.
- AI agents must always pass **`--no-interactive`** and an explicit **`--worktree`** name.
- Do not manually create worktrees — `start-development` is the single entry point
  for new work.

---

## Language & Runtime

- **Python ≥ 3.12** (`.python-version`, `requires-python = ">=3.12"`).
- Use **modern typing**: `list[str]`, `str | None`, not `List[str]` / `Optional[str]`.
- Every public function and method has complete type annotations. **pyright** enforces this.
- **Only `uv`** for Python dependency management. Never `pip` directly.
- The lock file (`uv.lock`) must always be committed.
- Shell scripts: no `.sh` extension; `#!/usr/bin/env bash`; `set -euo pipefail`;
  lowercase locals; pass `shellcheck`.

---

## Development

```bash
uv sync --group dev
uv run ruff check src tests
uv run ruff format --check src tests
uv run pyright
uv run pytest
```

---

## Commits, Stacking & Pull Requests

> Stacking SSOT: [`.agents/rules/stacking-tool.md`](./.agents/rules/stacking-tool.md)
> (marker `.github/stacking-tool` = `gh-stack`). Skill:
> [repository-helpers gh-stack](https://github.com/the-hcma/repository-helpers/blob/main/.agents/skills/gh-stack/SKILL.md).

- This project uses **`gh stack`** (GitHub Stacked PRs) for branch stacking.
- **Worktree-per-stack.** Every new stack is created via
  `start-development --worktree <name> --no-interactive`.
- Never work directly on `main`. Create stacked branches with
  `gh stack init <stack>/<topic>` then commit; add layers with `gh stack add`.
- Keep each branch focused on one logical change; **one commit per PR layer**.
- Submit with `~/work/ai/repository-helpers/scripts/dev/submit-stack`
  (or `gh stack submit --auto --open --remote origin`).
- Merge path: GitHub auto-merge (`gh pr merge --auto --squash`). **Never**
  `merge-it` / Graphite enqueue labels.
- Follow **Conventional Commits**: `feat:`, `fix:`, `chore:`, `docs:`, `test:`, `refactor:`.
- PR descriptions must include **Summary** and **Test plan** at minimum.
- Ship / agent-review flow: `.agents/rules/pr-ship-and-review.md` and the
  canonical [ship-and-review skill](https://github.com/the-hcma/repository-helpers/blob/main/.agents/skills/ship-and-review/SKILL.md).

---

## Repository Practices

Run from [repository-helpers](https://github.com/the-hcma/repository-helpers):

```bash
~/work/ai/repository-helpers/scripts/github-repo-lint --repo the-hcma/tiny-pki --suggest --strict-onboarding
```

After workflow or org-config edits, see
`.agents/rules/repo-practices-after-config-change.md`.

---

## Security

- Never commit CA private keys, client keys, PKCS#12 passwords, or live store dirs.
- CLI store paths must be explicit (`--store` / `TINY_PKI_STORE`); do not invent a
  surprise default on shared hosts.
- See `.agents/rules/no-secret-exposure.md`.
