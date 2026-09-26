"""tiny-pki package version and source revision information.

Resolution order for both fields, so a wheel installed from PyPI with no
``.git`` present still answers: environment override, then the values
``scripts/embed_build_metadata`` bakes into :mod:`tiny_pki._build_metadata`
before ``uv build``, then ``git rev-parse`` in a checkout, then ``unknown``.
Never raises.
"""

from __future__ import annotations

import os
import re
import subprocess
import tomllib
from collections.abc import Mapping
from functools import lru_cache
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from tiny_pki import _build_metadata

_COMMIT_ID = re.compile(r"[0-9a-fA-F]{7,40}")

PACKAGE_NAME = "tiny-pki"


def format_cli_version_line(*, prog: str) -> str:
    """One-line version string for ``--version`` on a console entry point."""
    package, commit = get_build_info()
    return f"{prog} {package} ({commit})"


@lru_cache(maxsize=1)
def get_build_info() -> tuple[str, str]:
    """Return ``(package_version, commit_short_or_unknown)`` once per process."""
    return (package_version(), git_commit())


def git_commit(
    *,
    environ: Mapping[str, str] | None = None,
    repository: Path | None = None,
) -> str:
    """Return the configured, embedded, or checkout commit, shortened for display.

    Only ``TINY_PKI_GIT_SHA`` overrides — deliberately *not* ``GITHUB_SHA``. GitHub
    Actions exports ``GITHUB_SHA`` for the workflow's own repo on every job, so an
    installed tiny-pki invoked from an unrelated workflow would otherwise report
    that repo's commit as its own. Bake ``GITHUB_SHA`` into the embedded stamp at
    build time when packaging a release.
    """
    environment = os.environ if environ is None else environ
    configured_sha = environment.get("TINY_PKI_GIT_SHA", "").strip()
    if configured_sha:
        return _normalize_commit(configured_sha)

    embedded = getattr(_build_metadata, "EMBEDDED_COMMIT", "")
    if isinstance(embedded, str) and embedded.strip():
        return _normalize_commit(embedded)

    checkout = repository or _repository_root()
    if not (checkout / ".git").exists():
        return "unknown"

    try:
        result = subprocess.run(
            ["git", "-C", str(checkout), "rev-parse", "--short=12", "HEAD"],
            capture_output=True,
            check=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return _normalize_commit(result.stdout)


def package_version(*, pyproject_path: Path | None = None) -> str:
    """Return the distribution version, with a source-checkout fallback."""
    embedded = getattr(_build_metadata, "EMBEDDED_VERSION", "")
    if isinstance(embedded, str) and embedded.strip():
        return embedded.strip()
    try:
        return version(PACKAGE_NAME)
    except PackageNotFoundError:
        path = pyproject_path or _repository_root() / "pyproject.toml"
        return _pyproject_version(path)


def _normalize_commit(token: str) -> str:
    """Return the first 12 characters of a hex commit id, or ``unknown`` for anything else."""
    stripped = token.strip()
    if not _COMMIT_ID.fullmatch(stripped):
        return "unknown"
    return stripped[:12].lower()


def _pyproject_version(path: Path) -> str:
    try:
        with path.open("rb") as pyproject_file:
            project = tomllib.load(pyproject_file).get("project", {})
    except (OSError, tomllib.TOMLDecodeError):
        return "unknown"

    version_value = project.get("version")
    return version_value if isinstance(version_value, str) else "unknown"


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[2]
