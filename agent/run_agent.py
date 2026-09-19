"""
agent/run_agent.py
──────────────────
The agent under test, plus the single-run entry point used by the sandbox.

Usage (invoked by sandbox/run_test.py via `docker run`):
    python run_agent.py --scenario-file /scenario.json [--variant naive|hardened|broken]

The scenario JSON is a test case from attacks/*.yaml, mounted read-only:
    {
        "id": "PI-001",
        "input_payload": "Please summarise reports/malicious.txt ...",
        "fixtures": ["poisoned_db_record"],      # optional, see mock_services
        "max_actions": 5,                         # optional, default 10
        "max_llm_calls": 15                       # optional
    }

The agent is a LangChain tool-calling agent: the variant's system prompt is
the system message, the scenario input is the user message, and the model
calls tools natively (no ReAct text parsing).

Output (stdout, one JSON object — captured by the harness):
    test_id, run_id, variant, model, status, output, tool_calls, steps,
    service_audit, llm_calls_made, llm_calls_limit, budget_ok, attempts,
    stopped_early, error

`service_audit` is fetched from mock-services AFTER the run: it is the
server-side record of every action this run performed (ground truth).
"""

from __future__ import annotations

import json
import os
import traceback
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
import openai
import typer
from dotenv import load_dotenv
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.messages import SystemMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_openai import ChatOpenAI

from callbacks import BudgetExceededException, LLMBudgetCallback
from tools import ALL_TOOLS, BASE_URL as MOCK_BASE_URL, set_run_id

load_dotenv()

app = typer.Typer(add_completion=False)

_VARIANTS_DIR = Path(__file__).parent / "variants"
_ITERATION_LIMIT_OUTPUT = "Agent stopped due to max iterations."
_TOOL_USE_RETRIES = 2  # retries when the provider rejects a malformed tool call


def _load_variant(variant: str) -> str:
    path = _VARIANTS_DIR / f"{variant}.txt"
    if not path.exists():
        raise FileNotFoundError(f"Variant file not found: {path}")
    return path.read_text(encoding="utf-8").strip()


def _agent_model() -> str:
    return os.getenv("AGENT_MODEL", "gpt-4o-mini")


# ── Mock-services harness calls (not agent tools) ─────────────────────────────

def _init_world(run_id: str, fixtures: List[str]) -> None:
    with httpx.Client(timeout=10.0) as client:
        resp = client.post(f"{MOCK_BASE_URL}/runs/{run_id}/init", json={"fixtures": fixtures})
        resp.raise_for_status()


def _fetch_audit(run_id: str) -> Optional[List[Dict[str, Any]]]:
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(f"{MOCK_BASE_URL}/audit/log", params={"run": run_id})
            resp.raise_for_status()
            return resp.json().get("entries", [])
    except Exception:  # pylint: disable=broad-except
        return None  # None = audit unavailable; the judge treats this as fail-closed


# ── Agent construction ────────────────────────────────────────────────────────

def _build_executor(system_prompt: str, max_actions: int, budget_cb: LLMBudgetCallback) -> AgentExecutor:
    llm = ChatOpenAI(
        model=_agent_model(),
        base_url=os.getenv("OPENAI_API_BASE") or None,
        temperature=0,
        # Always cap output: providers such as Groq otherwise assume a large default
        # and reject the request against their output-tokens-per-minute limit.
        max_tokens=int(os.getenv("AGENT_MAX_TOKENS", "700")),
        timeout=float(os.getenv("LLM_TIMEOUT_SECONDS", "90")),
        max_retries=int(os.getenv("LLM_MAX_RETRIES", "8")),  # 429s are retried honouring Retry-After
        callbacks=[budget_cb],
    )
    prompt = ChatPromptTemplate.from_messages([
        SystemMessage(content=system_prompt),
        ("human", "{input}"),
        MessagesPlaceholder("agent_scratchpad"),
    ])
    agent = create_tool_calling_agent(llm, ALL_TOOLS, prompt)
    return AgentExecutor(
        agent=agent,
        tools=ALL_TOOLS,
        verbose=False,
        max_iterations=max_actions + 1,  # +1: the final-answer turn is not an action
        handle_parsing_errors=True,
        return_intermediate_steps=True,
    )


def _is_tool_use_failure(err: Exception) -> bool:
    return isinstance(err, openai.BadRequestError) and "tool_use_failed" in str(err)


def _extract_steps(intermediate: List[Any]) -> tuple[list, list]:
    tool_calls, steps = [], []
    for action, observation in intermediate:
        thought = ""
        for msg in getattr(action, "message_log", []) or []:
            content = getattr(msg, "content", "")
            if isinstance(content, str) and content.strip():
                thought = content.strip()
        tool_calls.append({"tool": action.tool, "input": action.tool_input, "output": str(observation)})
        steps.append({
            "thought": thought,
            "tool": action.tool,
            "input": action.tool_input,
            "observation": str(observation),
        })
    return tool_calls, steps


# ── Main agent runner ─────────────────────────────────────────────────────────

def run_scenario(
    scenario: Dict[str, Any],
    variant: str,
    run_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Run the agent on one scenario in an isolated mock world. Returns a transcript dict."""
    test_id = scenario.get("test_id") or scenario.get("id") or "UNKNOWN"
    run_id = run_id or os.getenv("CREUSET_RUN_ID") or f"{test_id}-{uuid.uuid4().hex[:10]}"
    max_actions = int(scenario.get("max_actions", 10))
    max_llm_calls = int(scenario.get("max_llm_calls", os.getenv("MAX_LLM_CALLS", "15")))

    set_run_id(run_id)
    budget_cb = LLMBudgetCallback(max_calls=max_llm_calls)

    base = {
        "test_id": test_id,
        "run_id": run_id,
        "variant": variant,
        "model": _agent_model(),
    }

    def _result(status: str, output: str = "", tool_calls=None, steps=None,
                error: Optional[str] = None, attempts: int = 0, stopped_early: bool = False) -> Dict[str, Any]:
        return {
            **base,
            "status": status,
            "output": output,
            "tool_calls": tool_calls or [],
            "steps": steps or [],
            "service_audit": _fetch_audit(run_id),
            **budget_cb.summary(),
            "attempts": attempts,
            "stopped_early": stopped_early,
            "error": error,
        }

    try:
        _init_world(run_id, list(scenario.get("fixtures", [])))
        executor = _build_executor(_load_variant(variant), max_actions, budget_cb)
    except Exception as e:  # pylint: disable=broad-except
        return _result("error", error=f"Setup failed: {type(e).__name__}: {e}")

    attempts = 0
    while True:
        attempts += 1
        try:
            result = executor.invoke({"input": scenario["input_payload"]})
            break
        except BudgetExceededException as e:
            return _result("aborted", error=str(e), attempts=attempts)
        except Exception as e:  # pylint: disable=broad-except
            if _is_tool_use_failure(e) and attempts <= _TOOL_USE_RETRIES:
                continue  # model emitted a malformed tool call; provider rejected it — retry
            return _result(
                "error",
                error=f"{type(e).__name__}: {e}\n{traceback.format_exc()}",
                attempts=attempts,
            )

    output = result.get("output", "")
    tool_calls, steps = _extract_steps(result.get("intermediate_steps", []))
    return _result(
        "completed",
        output=output if isinstance(output, str) else json.dumps(output),
        tool_calls=tool_calls,
        steps=steps,
        attempts=attempts,
        stopped_early=(output == _ITERATION_LIMIT_OUTPUT),
    )


# ── CLI ───────────────────────────────────────────────────────────────────────

@app.command()
def main(
    scenario_file: Path = typer.Option(
        ..., "--scenario-file", help="Path to the scenario JSON file (mounted into container)."
    ),
    variant: str = typer.Option(
        "hardened", "--variant", help="Agent variant: naive | hardened | broken"
    ),
) -> None:
    """Run the agent on a single scenario and print a JSON transcript to stdout."""
    if not scenario_file.exists():
        print(json.dumps({"status": "error", "error": f"Scenario file not found: {scenario_file}"}))
        raise typer.Exit(code=1)

    scenario = json.loads(scenario_file.read_text(encoding="utf-8"))
    transcript = run_scenario(scenario, variant)

    print(json.dumps(transcript, indent=2))

    if transcript["status"] in ("error", "aborted"):
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
