"""
Every relative link in the Markdown docs resolves, anchors included.

CONTRIBUTING.md and the attack-case issue template linked to a guide that did
not exist for a whole release; this keeps that from happening again.
"""

import re

import pytest

from conftest import ROOT

DOCS = sorted([*ROOT.glob("*.md"), *ROOT.glob("docs/**/*.md"), *ROOT.glob("deploy/*.md")])
_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)\)")
_FENCE = re.compile(r"```.*?```", re.S)


def _slug(heading: str) -> str:
    """GitHub's heading anchor: lower-case, punctuation dropped, spaces to hyphens."""
    text = re.sub(r"[`*_]|\[([^\]]*)\]\([^)]*\)", r"\1", heading.strip().lower())
    return re.sub(r"[^\w\- ]", "", text).replace(" ", "-")


def _anchors(path):
    text = _FENCE.sub("", path.read_text(encoding="utf-8"))
    return {_slug(m.group(1)) for m in re.finditer(r"^#{1,6}\s+(.+?)\s*$", text, re.M)}


def _links():
    for doc in DOCS:
        text = _FENCE.sub("", doc.read_text(encoding="utf-8"))
        for target in _LINK.findall(text):
            if re.match(r"[a-z]+:", target):   # http(s):, mailto:
                continue
            yield pytest.param(doc, target, id=f"{doc.relative_to(ROOT).as_posix()} -> {target}")


@pytest.mark.parametrize("doc, target", list(_links()))
def test_relative_link_resolves(doc, target):
    path, _, anchor = target.partition("#")
    resolved = (doc.parent / path).resolve() if path else doc
    assert resolved.exists(), f"{target} does not exist"
    if anchor and resolved.suffix == ".md":
        assert anchor in _anchors(resolved), f"no heading for #{anchor} in {resolved.name}"


def test_the_guides_are_linked_from_somewhere_a_reader_starts():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "docs/guides/testing-your-agent.md" in readme
    assert "docs/guides/writing-attack-cases.md" in (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
