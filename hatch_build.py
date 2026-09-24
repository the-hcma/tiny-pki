"""Hatchling build hook: bake version/commit into ``tiny_pki._build_metadata``.

Runs ``scripts/embed_build_metadata`` before the wheel/sdist is assembled so
installs without a ``.git`` directory still report a useful
``tiny-pki --version`` line. Restores the empty stub afterwards so a local
``uv build`` does not leave a dirty working tree.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class BuildMetadataHook(BuildHookInterface):
    """Embed package version + short SHA, then restore the empty stub."""

    PLUGIN_NAME = "custom"

    def finalize(self, version: str, build_data: dict[str, Any], artifact_path: str) -> None:
        del version, build_data, artifact_path
        self._run_embed(version="", commit="")

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        del version, build_data
        embed_version = os.environ.get("TINY_PKI_EMBED_VERSION", "").strip()
        if not embed_version:
            embed_version = str(self.metadata.version)
        embed_commit = os.environ.get("TINY_PKI_EMBED_COMMIT", "").strip()
        if not embed_commit:
            embed_commit = self._git_short_sha()
        if not embed_commit:
            # Preserve a stamp already present (e.g. wheel built from an sdist
            # that was packed with a commit, then rebuilt without ``.git``).
            embed_commit = self._existing_embedded_commit()
        self._run_embed(version=embed_version, commit=embed_commit)

    def _existing_embedded_commit(self) -> str:
        path = Path(self.root) / "src" / "tiny_pki" / "_build_metadata.py"
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            return ""
        for line in text.splitlines():
            if line.startswith("EMBEDDED_COMMIT:"):
                # EMBEDDED_COMMIT: str = "abc..." or ''
                _, _, rhs = line.partition("=")
                return rhs.strip().strip("\"'")
        return ""

    def _git_short_sha(self) -> str:
        root = Path(self.root)
        if not (root / ".git").exists():
            return ""
        try:
            result = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "--short=12", "HEAD"],
                capture_output=True,
                check=True,
                text=True,
                timeout=2,
            )
        except (OSError, subprocess.SubprocessError):
            return ""
        return result.stdout.strip()

    def _run_embed(self, *, version: str, commit: str) -> None:
        script = Path(self.root) / "scripts" / "embed_build_metadata"
        env = os.environ.copy()
        env["TINY_PKI_EMBED_VERSION"] = version
        env["TINY_PKI_EMBED_COMMIT"] = commit
        # Already under the build env; avoid nested ``uv run`` re-exec.
        env["UV_ACTIVE"] = "1"
        subprocess.run(
            [sys.executable, str(script)],
            check=True,
            cwd=str(self.root),
            env=env,
        )
