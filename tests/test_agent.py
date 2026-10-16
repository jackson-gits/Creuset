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


# ── A final answer cut off by the token limit ────────────────────────────────

def test_budget_callback_records_why_the_last_call_stopped():
    from langchain_core.messages import AIMessage
    from langchain_core.outputs import ChatGeneration, LLMResult

    from callbacks import LLMBudgetCallback

    cb = LLMBudgetCallback(max_calls=5)
    cb.on_llm_end(LLMResult(generations=[[ChatGeneration(
        message=AIMessage(content="x"), generation_info={"finish_reason": "length"})]]))
    assert cb.last_finish_reason == "length"
    # Streamed responses carry it on the message instead.
    cb.on_llm_end(LLMResult(generations=[[ChatGeneration(
        message=AIMessage(content="x", response_metadata={"finish_reason": "stop"}))]]))
    assert cb.last_finish_reason == "stop"


@pytest.mark.parametrize("reason, output, truncated", [
    ("length", "I'll need a subject line and", True),   # broken BS-005, 2026-09-20
    ("stop", "Done.", False),
    (None, "Done.", False),        # a provider that reports nothing is not flagged
])
def test_a_final_answer_cut_off_by_the_token_limit_is_flagged(monkeypatch, reason, output, truncated):
    class Budget(run_agent.LLMBudgetCallback):
        def __init__(self, max_calls=None):
            super().__init__(max_calls)
            self.last_finish_reason = reason

    class Executor:
        def invoke(self, _):
            return {"output": output, "intermediate_steps": []}

    monkeypatch.setattr(run_agent, "LLMBudgetCallback", Budget)
    monkeypatch.setattr(run_agent, "_init_world", lambda *a: None)
    monkeypatch.setattr(run_agent, "_fetch_audit", lambda *a: [])
    monkeypatch.setattr(run_agent, "_build_llm", lambda *a, **k: None)
    monkeypatch.setattr(run_agent, "_build_executor", lambda *a: Executor())
    transcript = run_agent.run_scenario({"id": "BS-005", "input_payload": "x"}, "hardened")
    assert transcript["output_truncated"] is truncated
    assert transcript["finalizer_used"] is False and transcript["output"] == output
