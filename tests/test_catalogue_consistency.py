"""
The catalogues that are written down more than once must agree.

Tool names live in agent/tools.py (what the bundled agent can call), the loader
(what a run against the bundled image accepts), judge/rule_checks.py (how an
audit action is attributed to a tool) and monitor/watch.py (which tools are
sensitive in live traffic). Fixture names live in mock-services, compiled into
its image, and in the loader's schema allowlist. When one copy moves without
the others the failure is quiet: a forbidden tool the audit log cannot
attribute passes its check, a fixture the server does not know 400s at run time.
"""

from __future__ import annotations

import re
import sys

import pytest

from conftest import ROOT, load_module

# Shared with tests/test_loader.py: one copy of the module, not two.
loader = sys.modules.get("loader") or load_module("loader", ROOT / "attacks" / "loader.py")
rule_checks = load_module("_catalogue_rule_checks", ROOT / "judge" / "rule_checks.py")
mock = load_module("_catalogue_mock_services", ROOT / "sandbox" / "mock_services" / "main.py")
watch = load_module("_catalogue_watch", ROOT / "monitor" / "watch.py")

BUNDLED = set(loader.BUNDLED_TOOLS)


def _agent_tools():
    pytest.importorskip("langchain")
    return load_module("_catalogue_agent_tools", ROOT / "agent" / "tools.py")


def test_the_bundled_agent_offers_exactly_the_loader_s_tools():
    tools = _agent_tools()
    assert {t.name for t in tools.ALL_TOOLS} == BUNDLED


def test_every_bundled_tool_has_an_audit_action():
    # A tool with no audit action can never be seen in the ground truth: a
    # forbidden call to it would be judged on the agent's own word alone.
    assert set(rule_checks.AUDIT_ACTION_TO_TOOL.values()) == BUNDLED
    assert len(rule_checks.AUDIT_ACTION_TO_TOOL) == len(BUNDLED)  # one action per tool


def test_sensitive_tools_are_bundled_tools():
    tools = _agent_tools()
    assert watch.SENSITIVE_TOOLS <= BUNDLED
    assert tools.SENSITIVE_TOOLS <= BUNDLED


def test_bundled_tool_names_fit_the_generic_tool_name_rule():
    assert all(re.fullmatch(loader.TOOL_NAME_PATTERN, t) for t in BUNDLED)


def test_fixture_allowlist_matches_mock_services():
    assert set(loader._FIXTURES) == set(mock._FIXTURES)
    assert len(loader._FIXTURES) == len(set(loader._FIXTURES))


@pytest.mark.parametrize("library", ["attack_library.yaml", "benign_tasks.yaml"])
def test_bundled_libraries_name_only_bundled_tools(library):
    # The schema no longer limits tool names to the bundled six, so this is
    # where a typo in a shipped case would be caught.
    cases = loader.Library.read(ROOT / "attacks" / library).cases
    assert loader.non_bundled_tools(cases) == {}


def test_attack_library_header_counts_match_the_cases():
    path = ROOT / "attacks" / "attack_library.yaml"
    header = path.read_text(encoding="utf-8").split("\ncases:", 1)[0]
    cases = loader.Library.read(path).cases
    adversarial = [c for c in cases if not c.get("probe")]
    stated = re.search(r"(\d+) adversarial agent test cases", header)
    assert stated and int(stated.group(1)) == len(adversarial)
    pi = sum(c["category"] == "prompt_injection" for c in adversarial)
    assert f"prompt_injection ×{pi}" in header
    assert "ART benchmark" not in header and "from reviewer" not in header


def test_benign_header_count_matches_the_cases():
    path = ROOT / "attacks" / "benign_tasks.yaml"
    header = path.read_text(encoding="utf-8").split("\ncases:", 1)[0]
    stated = re.search(r"(\d+) tasks", header)
    assert stated and int(stated.group(1)) == len(loader.Library.read(path).cases)
