"""CI wrappers re-exec through with-tmp-layout (repository-helpers#832)."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest
from hamcrest import assert_that, contains_string, equal_to, has_item

_ROOT = Path(__file__).resolve().parent.parent
_CI = _ROOT / ".github" / "ci"
_WORKFLOWS = _ROOT / ".github" / "workflows"
_ACTION = "the-hcma/repository-helpers/actions/setup-tmp-layout@"
_TOOLS = {
    "packaging": ["uv"],
    "pytest-cryptography-minimum": ["uv", "pytest"],
    "pytest-hermetic": ["uv", "pytest"],
    "python-static": ["uv"],
}


def _env(tmp_path: Path, helpers: Path, **extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in {"CI_TMP_LAYOUT", "GITHUB_ACTIONS"}}
    env.update({"HOME": str(tmp_path), "REPOSITORY_HELPERS_DIR": str(helpers), "TMPDIR": str(tmp_path)})
    env.update(extra)
    return env


def _run(wrapper: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["bash", str(_CI / wrapper)], cwd=_ROOT, env=env, text=True, capture_output=True, check=False)


@pytest.mark.parametrize("wrapper", sorted(_TOOLS))
def test_ci_without_the_layout_helper_fails_with_a_pointer_to_the_action(tmp_path: Path, wrapper: str) -> None:
    run = _run(wrapper, _env(tmp_path, tmp_path / "none", GITHUB_ACTIONS="true"))
    assert_that(run.returncode, equal_to(1))
    assert_that(run.stderr, contains_string("setup-tmp-layout"))


@pytest.mark.parametrize("wrapper", sorted(_TOOLS))
def test_the_layout_helper_wraps_the_wrapper_in_its_tool_layouts(tmp_path: Path, wrapper: str) -> None:
    helpers = tmp_path / "helpers"
    (helpers / "scripts" / "dev").mkdir(parents=True)
    fake = helpers / "scripts" / "dev" / "with-tmp-layout"
    # Record the layout tools, then stop: the wrapper body itself needs uv and the network.
    fake.write_text(
        "#!/usr/bin/env bash\n"
        'printf "%s\\n" "$1" >> "$TMPDIR/layout-tools"\n'
        "shift 2\n"
        'if [[ "$1" == "$0" ]]; then exec "$@"; fi\n'
    )
    fake.chmod(0o755)
    run = _run(wrapper, _env(tmp_path, helpers))
    assert_that(run.returncode, equal_to(0))
    recorded = (tmp_path / "layout-tools").read_text().split()
    assert_that(recorded, equal_to(_TOOLS[wrapper]))


def test_every_job_that_runs_a_layout_wrapper_sets_up_the_layout_first() -> None:
    wrappers = tuple(f".github/ci/{name}" for name in _TOOLS)
    checked = 0
    for workflow in sorted(_WORKFLOWS.glob("*.yml")):
        text = workflow.read_text(encoding="utf-8")
        for job in re.split(r"\n(?=  [a-z][a-z0-9-]*:\n)", text):
            first_run = min((job.find(w) for w in wrappers if w in job), default=-1)
            if first_run < 0:
                continue
            checked += 1
            action = job.find(_ACTION)
            assert_that(action >= 0 and action < first_run, equal_to(True), f"{workflow.name}: {job[:40]!r}")
            assert_that(
                re.findall(rf"{re.escape(_ACTION)}(\w+)\n", job), has_item("bfee0e1f2d682e83c6207a0d6a0f7feefa576fd8")
            )
    assert_that(checked >= 5, equal_to(True))
