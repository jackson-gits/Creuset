"""
agent/callbacks.py
──────────────────
LangChain callback handler that enforces a hard cap on the number of LLM calls
an agent may make per test run.

When MAX_LLM_CALLS is exceeded:
  - A BudgetExceededException is raised, bubbling up to run_agent.py
  - The transcript is marked ABORTED: llm_budget_exceeded
  - The gate treats this as a FAIL (fail-closed)

This guards against cost-runaway scenarios (agent loops, adversarial inputs
that induce repeated retries) that don't hit CPU/memory limits but still
consume real money.
"""

from __future__ import annotations

import os
import threading
from typing import Any, Dict, List, Optional, Union

from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.outputs import LLMResult


class BudgetExceededException(Exception):
    """Raised when the per-run LLM call budget is exhausted."""

    def __init__(self, limit: int) -> None:
        super().__init__(
            f"LLM call budget exceeded: max_llm_calls={limit}. "
            "Run aborted. Gate treats this as FAIL (fail-closed)."
        )
        self.limit = limit


class LLMBudgetCallback(BaseCallbackHandler):
    """
    Thread-safe LangChain callback that counts LLM calls and raises
    BudgetExceededException when the configured limit is hit.

    Usage:
        budget = LLMBudgetCallback(max_calls=15)
        llm = ChatOpenAI(callbacks=[budget])
    """

    # LangChain swallows (and only logs) exceptions raised inside callback
    # handlers unless raise_error is True — without this the budget would
    # never actually stop a run.
    raise_error = True

    def __init__(self, max_calls: Optional[int] = None) -> None:
        super().__init__()
        self.max_calls: int = max_calls or int(
            os.getenv("MAX_LLM_CALLS", "15")
        )
        self._call_count: int = 0
        self._lock = threading.Lock()

    # ── Properties ────────────────────────────────────────────────────────

    @property
    def call_count(self) -> int:
        with self._lock:
            return self._call_count

    # ── LangChain hooks ───────────────────────────────────────────────────

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        **kwargs: Any,
    ) -> None:
        with self._lock:
            self._call_count += 1
            count = self._call_count

        if count > self.max_calls:
            raise BudgetExceededException(self.max_calls)

    def on_llm_end(self, response: LLMResult, **kwargs: Any) -> None:
        pass  # nothing extra needed on completion

    def on_llm_error(
        self,
        error: Union[Exception, KeyboardInterrupt],
        **kwargs: Any,
    ) -> None:
        pass  # errors counted on on_llm_start; no double-count needed

    # ── Summary ───────────────────────────────────────────────────────────

    def summary(self) -> Dict[str, Any]:
        return {
            "llm_calls_made": self.call_count,
            "llm_calls_limit": self.max_calls,
            "budget_ok": self.call_count <= self.max_calls,
        }
