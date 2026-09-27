"""Documentation stays in step with the CLI flag table, and its links resolve."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import re
from pathlib import Path

import pytest
from hamcrest import assert_that, empty, equal_to, is_

from tiny_pki.cli.commands import COMMAND_FLAGS, COMMANDS

_ROOT = Path(__file__).resolve().parents[1]
_DOCS = sorted([_ROOT / "README.md", _ROOT / "SECURITY.md", _ROOT / "CHANGELOG.md", *(_ROOT / "docs").glob("*.md")])
_GITHUB_BLOB = "https://github.com/the-hcma/tiny-pki/blob/main/"
_LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
_FENCE = re.compile(r"^```.*?^```", re.MULTILINE | re.DOTALL)


def _cli_sections() -> dict[str, str]:
    """docs/cli.md split at every heading, keyed by the heading text."""
    text = _FENCE.sub("", (_ROOT / "docs" / "cli.md").read_text(encoding="utf-8"))
    parts = re.split(r"^#{1,6} (.+)\n", text, flags=re.MULTILINE)
    return dict(zip(parts[1::2], parts[2::2], strict=True))


def _table_flags(section: str) -> set[str]:
    return set(re.findall(r"^\| `(--[\w-]+)", section, flags=re.MULTILINE))


def _slug(heading: str) -> str:
    """GitHub's anchor for a heading: lower case, punctuation dropped (``_`` kept), spaces to ``-``."""
    return re.sub(r"[^\w\- ]", "", heading.strip().lower()).replace(" ", "-")


def _anchors(path: Path) -> set[str]:
    """Every anchor GitHub generates for ``path``, including ``-1``, ``-2``... for repeated headings."""
    text = _FENCE.sub("", path.read_text(encoding="utf-8"))
    seen: dict[str, int] = {}
    anchors: set[str] = set()
    for match in re.finditer(r"^#{1,6} (.+)$", text, flags=re.MULTILINE):
        slug = _slug(match.group(1))
        count = seen.get(slug, 0)
        seen[slug] = count + 1
        anchors.add(f"{slug}-{count}" if count else slug)
    return anchors


def test_slug_matches_github() -> None:
    assert_that(_slug("Optional: `tiny_pki.secrets`"), equal_to("optional-tiny_pkisecrets"))
    assert_that(_slug("`list --json`"), equal_to("list---json"))
    assert_that(_slug("Key types, sizes and validity"), equal_to("key-types-sizes-and-validity"))


@pytest.mark.parametrize("command", sorted(set(COMMAND_FLAGS) - {"renew-crl"}))
def test_cli_reference_flag_table_matches_command_flags(command: str) -> None:
    sections = _cli_sections()
    assert command in sections, f"docs/cli.md has no '### {command}' section"
    assert_that(_table_flags(sections[command]), equal_to({f.option for f in COMMAND_FLAGS[command]}))


def test_cli_sections_ignore_comments_in_code_blocks() -> None:
    assert_that([k for k in _cli_sections() if k.startswith("install")], is_(empty()))


def test_cli_reference_mentions_every_command() -> None:
    text = (_ROOT / "docs" / "cli.md").read_text(encoding="utf-8")
    sections = _cli_sections()
    missing = [c for c in COMMANDS if c not in sections and f"`{c}" not in text]
    assert_that(missing, is_(empty()))


@pytest.mark.parametrize("doc", _DOCS, ids=lambda p: str(p.relative_to(_ROOT)))
def test_links_resolve(doc: Path) -> None:
    broken: list[str] = []
    for target in _LINK.findall(_FENCE.sub("", doc.read_text(encoding="utf-8"))):
        if target.startswith(_GITHUB_BLOB):
            target = str(_ROOT / target.removeprefix(_GITHUB_BLOB))
        elif target.startswith(("http://", "https://", "mailto:")):
            continue
        file_part, _, anchor = target.partition("#")
        path = doc if not file_part else (doc.parent / file_part).resolve()
        if not path.exists() or (anchor and path.suffix == ".md" and anchor not in _anchors(path)):
            broken.append(target)
    assert_that(broken, is_(empty()))
