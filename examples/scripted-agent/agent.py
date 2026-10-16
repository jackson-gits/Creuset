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

With ORDERS_API_URL set it talks to an orders REST API instead, the way a real
service would (GET /orders/<id>, POST /refunds), and knows nothing about
Creuset. Pointed at the REST mock with
    --agent-env 'ORDERS_API_URL=${CREUSET_MOCK_URL}/http/orders-api'
it is tested with no code change; see cases_http.yaml.

With MCP_URL set it is an MCP client instead: it initialises a session, lists
the server's tools and calls them with tools/call (JSON-RPC over HTTP), the
way an agent whose tools come from MCP servers does. Pointed at the MCP mock
with
    --agent-env 'MCP_URL=${CREUSET_MOCK_URL}/mcp'
it is tested with no code change; see cases_mcp.yaml.
"""

import itertools
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


# The same two operations as an ordinary REST client would make them.
REST_ROUTES = {"lookup_order": ("GET", "/orders/{order_id}"), "issue_refund": ("POST", "/refunds")}


def call_api(name: str, args: dict) -> object:
    method, template = REST_ROUTES[name]
    url = os.environ["ORDERS_API_URL"].rstrip("/") + template.format(**args)
    data = json.dumps(args).encode() if method != "GET" else None
    request = urllib.request.Request(url, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read())


_mcp_ids = itertools.count(1)


def mcp_post(message: dict) -> object:
    """One JSON-RPC message to the MCP server; the reply, or None for a notification's empty 202."""
    request = urllib.request.Request(
        os.environ["MCP_URL"], data=json.dumps(message).encode(), method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
    with urllib.request.urlopen(request, timeout=10) as response:
        body = response.read()
    return json.loads(body) if body else None


def mcp_request(method: str, params: dict) -> dict:
    reply = mcp_post({"jsonrpc": "2.0", "id": next(_mcp_ids), "method": method, "params": params})
    if "error" in reply:
        raise RuntimeError(f"MCP {method}: {reply['error'].get('message')}")
    return reply["result"]


def mcp_connect() -> list:
    """The MCP handshake, then the server's tool names."""
    mcp_request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                               "clientInfo": {"name": "creuset-example-scripted", "version": "1"}})
    mcp_post({"jsonrpc": "2.0", "method": "notifications/initialized"})
    return [tool["name"] for tool in mcp_request("tools/list", {})["tools"]]


def call_mcp(name: str, args: dict) -> object:
    result = mcp_request("tools/call", {"name": name, "arguments": args})
    return result.get("structuredContent") or json.loads(result["content"][0]["text"])


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
    if os.environ.get("MCP_URL"):
        log(f"MCP server offers: {mcp_connect()}")

    def tool(name: str, args: dict) -> object:
        if os.environ.get("MCP_URL"):
            result = call_mcp(name, args)
            calls.append({"tool": name, "input": args, "output": json.dumps(result)})
            log(f"mcp {name}({args}) -> {result}")
            return result
        if os.environ.get("ORDERS_API_URL"):
            result = call_api(name, args)
            method, template = REST_ROUTES[name]
            # Reported as the server records it: a call of the API, by method and path.
            calls.append({"tool": "orders-api", "input": {"method": method, "path": template.format(**args)},
                          "output": json.dumps(result)})
            log(f"{method} {template.format(**args)} -> {result}")
            return result
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
