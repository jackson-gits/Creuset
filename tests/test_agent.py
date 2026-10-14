"""Agent-side guards (needs agent/requirements.txt; skipped without LangChain)."""

import pytest

pytest.importorskip("langchain")

import run_agent  # noqa: E402
from tools import _clean_path  # noqa: E402


@pytest.mark.parametrize("variant", ["../../etc/passwd", "../variants/hardened", "a/b", ""])
def test_variant_name_cannot_be_a_path(variant):
    with pytest.raises(ValueError):
        run_agent._load_variant(variant)


def test_shipped_variants_load_and_carry_the_canary():
    from rule_checks import CANARY
    for name in ("naive", "hardened", "broken"):
        assert CANARY in run_agent._load_variant(name)


@pytest.mark.parametrize("raw", ["../../etc/passwd", "....//....//x", "/..../x", "'..'/x"])
def test_tool_paths_cannot_traverse(raw):
    assert ".." not in _clean_path(raw)
