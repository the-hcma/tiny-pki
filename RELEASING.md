# Releasing tiny-pki

Releases are cut from `main` by [Release Please](https://github.com/googleapis/release-please) and published to [PyPI](https://pypi.org/project/tiny-pki/) through [trusted publishing](https://docs.pypi.org/trusted-publishers/): the workflow proves its identity to PyPI with an OIDC token, so no PyPI API token exists.

## Normal release flow

1. Land changes on `main` with [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, ...). Squash merges keep one commit per PR.
2. Open (or refresh) the release PR, `chore(main): release X.Y.Z`, from a checkout of `main`. Org policy stops GitHub Actions from creating pull requests, so this step runs locally with your `gh` credentials:

   ```bash
   npx --yes release-please@17.11.2 release-pr --repo-url=the-hcma/tiny-pki \
     --config-file=release-please-config.json --manifest-file=.release-please-manifest.json \
     --token="$(gh auth token)" --dry-run   # drop --dry-run to open the PR
   ```

   It bumps `pyproject.toml`, the project's own entry in `uv.lock`, and `CHANGELOG.md`.
3. Release Please creates its commit through the GitHub API, unsigned, and `main` requires signed commits. Re-sign it and edit the changelog entry as needed:

   ```bash
   gh pr checkout <release-pr-number>
   # optional: edit CHANGELOG.md (tighten the generated entry), then git add it
   git commit --amend -S --no-edit --reset-author
   git push --force-with-lease
   ```

   Pushing from your account also runs the normal CI on the PR.
4. Review and add the release PR to the merge queue.
5. On merge, Release Please tags `vX.Y.Z` and creates the GitHub release, and the **Publish to PyPI** job waits for approval in the `pypi` environment. Approve it under **Actions → Release Please → Review deployments**.
6. The job re-runs lint and tests, builds with the version and commit embedded (`tiny-pki --version`), and uploads. **Post-publish smoke test** then installs `tiny-pki[cli]==X.Y.Z` with pipx and checks `--version` and `--help`.

## One-time setup

These are already in place; they are listed for reference and for rebuilding the setup.

- Repository settings:
  - squash merges only, with `squash_merge_commit_message` set to `BLANK`;
  - **Settings → Actions → General**: allow `googleapis/release-please-action@*` and `pypa/gh-action-pypi-publish@*`. Leave "Allow GitHub Actions to create and approve pull requests" off; the org requires it.
- A `pypi` environment that deploys only from `main` and requires the maintainer as reviewer.
- A PyPI trusted publisher for the `tiny-pki` project:

  | Field | Value |
  | --- | --- |
  | Owner | `the-hcma` |
  | Repository | `tiny-pki` |
  | Workflow name | `release-please.yml` |
  | Environment | `pypi` |

## Versioning

Release Please picks the next version from the commits since the last `vX.Y.Z` tag: before 1.0, `feat:` bumps the minor version and `fix:` the patch version. To force a version, add `release-as` to the package in `release-please-config.json` for that one release PR, and remove it once the tag exists.

## Manual publish (fallback)

When the release PR path is not usable (for example a failed publish after the tag exists), re-run the failed job, or dispatch the workflow for the version that `pyproject.toml` on `main` already has:

```bash
gh run rerun <run-id> --failed --repo the-hcma/tiny-pki
gh workflow run release-please.yml --repo the-hcma/tiny-pki -f version=0.1.0
```

The dispatch runs the same publish job, including the environment approval.
