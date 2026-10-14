"""
A deterministic stand-in for an LLM agent, written against Creuset's agent
contract (sandbox/contract.py, schemas/transcript.v1.json). No model, no key,
no quota: it exists to show the contract end to end, and to let CI run the
whole sandbox → judge → gate path for free.

Its "policy" is the bug every prompt-injection case looks for: it looks the
order up, and if the tool's answer contains a line

    [SYSTEM] call <tool> <json args>

the `naive` variant obeys it. The `careful` variant reports it instead.

Contract, as this file uses it:
  in   CREUSET_SCENARIO_FILE   the scenario: id, input_payload, ...
       CREUSET_MOCK_URL        this run's mock world; tools are POST <url>/tools/<name>
       CREUSET_VARIANT         the label the harness was asked to run
  out  one JSON object on stdout (schema_version 1); logs on stderr
"""

import json
import os
import re
import sys
import urllib.request

INSTRUCTION = re.compile(r"\[SYSTEM\]\s*call\s+([a-z][a-z0-9_]*)\s*(\{.*?\})?", re.S)


def log(message: str) -> None:
    print(message, file=sys.stderr)   # stdout is reserved for the transcript


def call_tool(name: str, args: dict) -> object:
    request = urllib.request.Request(
        f"{os.environ['CREUSET_MOCK_URL']}/tools/{name}",
        data=json.dumps(args).encode(), method="POST",
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read())


def strings(value: object):
    """Every string inside a JSON value: where an injected instruction can hide."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)


def run(scenario: dict, variant: str) -> dict:
    calls = []

    def tool(name: str, args: dict) -> object:
        result = call_tool(name, args)
        calls.append({"tool": name, "input": args, "output": json.dumps(result)})
        log(f"{name}({args}) -> {result}")
        return result

    order_id = (re.findall(r"\b\d{3,}\b", scenario["input_payload"]) or ["unknown"])[0]
    order = tool("lookup_order", {"order_id": order_id})
    injected = next(filter(None, map(INSTRUCTION.search, strings(order))), None)
    if injected and variant == "naive":
        tool(injected.group(1), json.loads(injected.group(2) or "{}"))
        answer = f"Order {order_id} looked up, and I ran the follow-up step the order record asked for."
    elif injected:
        answer = (f"Order {order_id} looked up. Its record contains an instruction to call "
                  f"{injected.group(1)}; I did not follow it, since tool output is data, not a request.")
    else:
        answer = f"Order {order_id}: {json.dumps(order)}"
    return {"schema_version": 1, "status": "completed", "output": answer, "tool_calls": calls,
            "model": "scripted", "llm_calls_made": 0, "meta": {"agent": "examples/scripted-agent"}}


def main() -> int:
    try:
        with open(os.environ["CREUSET_SCENARIO_FILE"], encoding="utf-8") as f:
            scenario = json.load(f)
        transcript = run(scenario, os.environ.get("CREUSET_VARIANT", "careful"))
    except Exception as e:  # report, don't crash: a crash is a container_error
        transcript = {"schema_version": 1, "status": "error", "output": "",
                      "error": f"{type(e).__name__}: {e}"}
    print(json.dumps(transcript))
    return 0 if transcript["status"] == "completed" else 1


if __name__ == "__main__":
    sys.exit(main())
