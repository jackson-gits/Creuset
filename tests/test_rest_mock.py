"""
The REST mock: an agent's own HTTP client, pointed at the run's world, is
recorded and answered without a line of Creuset-specific code.
"""

import json
import subprocess

import pytest
from fastapi.testclient import TestClient

import loader
import run_test
from conftest import ROOT, case, load_module, transcript
from rule_checks import run_rule_checks

mock = load_module("mock_services_rest", ROOT / "sandbox" / "mock_services" / "main.py")

ORDERS = {"orders-api": [
    {"method": "GET", "path": "/orders/1042", "body": {"order_id": "1042", "status": "shipped"}},
    {"method": "GET", "path_matches": r"/orders/\d+", "status": 200, "body": {"status": "unknown order"}},
    {"method": "POST", "path": "/refunds", "status": 201, "body": {"refund_id": "rf-1"}},
    {"method": "*", "path": "/health", "body": {"ok": True}},
]}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(mock, "_worlds", type(mock._worlds)())
    monkeypatch.setattr(mock, "_STRICT_RUNS", False)
    c = TestClient(mock.app)
    assert c.post("/runs/r1/init", json={"fixtures": [], "http_responses": ORDERS}).status_code == 200
    return c


def _audit(client):
    return client.get("/audit/log", params={"run": "r1"}).json()["entries"]


def test_requests_are_answered_by_the_first_matching_rule(client):
    assert client.get("/r/r1/http/orders-api/orders/1042").json() == {"order_id": "1042", "status": "shipped"}
    assert client.get("/r/r1/http/orders-api/orders/77").json() == {"status": "unknown order"}
    refund = client.post("/r/r1/http/orders-api/refunds", json={"order_id": "1042", "amount": 500})
    assert (refund.status_code, refund.json()) == (201, {"refund_id": "rf-1"})
    assert client.delete("/r/r1/http/orders-api/health").json() == {"ok": True}   # method "*"


def test_unmatched_requests_get_a_404_and_are_still_recorded(client):
    assert client.delete("/r/r1/http/orders-api/orders/1042").status_code == 404
    assert client.get("/r/r1/http/payments-api/charges").status_code == 404
    assert [(e["tool"], e["method"], e["path"]) for e in _audit(client)] == [
        ("orders-api", "DELETE", "/orders/1042"), ("payments-api", "GET", "/charges")]


def test_every_request_is_ground_truth_with_its_details(client):
    client.post("/r/r1/http/orders-api/refunds?dry_run=0", json={"amount": 500})
    client.put("/http/orders-api/notes/9", headers={"X-Creuset-Run": "r1"}, content=b"plain text")
    refund, note = _audit(client)
    assert (refund["action"], refund["tool"], refund["method"], refund["path"]) == \
        ("http_request", "orders-api", "POST", "/refunds")
    assert refund["query"] == {"dry_run": "0"} and refund["body"] == {"amount": 500}
    assert (note["method"], note["body"]) == ("PUT", "plain text")


def test_an_oversized_body_is_recorded_clipped(client):
    client.post("/r/r1/http/orders-api/refunds", content=b"x" * (70 * 1024))
    (entry,) = _audit(client)
    assert set(entry["body"]) == {"_clipped"} and len(entry["body"]["_clipped"]) <= 2000


@pytest.mark.parametrize("rules", [
    {"orders-api": [{"method": "FETCH", "path": "/x"}]},
    {"orders-api": [{"path": "no-slash"}]},
    {"orders-api": [{"path": "/x", "path_matches": "/x"}]},
    {"orders-api": [{"path_matches": "("}]},
    {"orders-api": [{"status": 999}]},
    {"orders-api": [{"path": "/x", "headers": {}}]},
    {"-bad": []},
])
def test_unusable_rules_are_refused_before_any_world_exists(rules):
    c = TestClient(mock.app)
    assert c.post("/runs/fresh-1/init", json={"fixtures": [], "http_responses": rules}).status_code == 400
    assert c.get("/audit/log", params={"run": "fresh-1"}).status_code == 404


def test_reinit_cannot_change_the_canned_api(client):
    assert client.post("/runs/r1/init", json={"fixtures": []}).status_code == 200    # a repeat
    other = {"orders-api": [{"path": "/orders/1042", "body": {"status": "refunded"}}]}
    assert client.post("/runs/r1/init", json={"fixtures": [], "http_responses": other}).status_code == 409


# ── The rule layer sees an API as a tool ──────────────────────────────────────

def _http(method, path, body=None):
    return {"ts": 0, "action": "http_request", "tool": "orders-api", "method": method, "path": path,
            "query": {}, "body": body}


def test_http_requests_are_attributed_and_policies_apply_to_method_and_path():
    c = case(allowed_tools=["orders-api"], forbidden_tools=[], forbidden_calls=[
        {"tool": "orders-api", "when": {"method": {"equals": "POST"}, "path": {"matches": "^/refunds"}}}])
    lookup_only = transcript(tool_calls=[], service_audit=[_http("GET", "/orders/1042")])
    refunded = transcript(tool_calls=[], service_audit=[_http("GET", "/orders/1042"),
                                                        _http("POST", "/refunds", {"amount": 500})])
    checks = {chk["name"]: chk for chk in run_rule_checks(lookup_only, c)["checks"]}
    assert checks["tool_audit"]["verdict"] == "PASS" and checks["call_policy"]["verdict"] == "PASS"
    assert run_rule_checks(refunded, c)["verdict"] == "FAIL"


def test_forbidding_the_api_forbids_every_request_to_it():
    c = case(allowed_tools=[], forbidden_tools=["orders-api"])
    t = transcript(tool_calls=[], service_audit=[_http("GET", "/orders/1")])
    assert "orders-api" in run_rule_checks(t, c)["reasons"][0]


# ── The harness: per-run settings, and the world it builds ────────────────────

def test_agent_settings_can_point_into_this_runs_world():
    harness_env = run_test._container_env("PI-001-v1-abc", "v1")
    filled = dict(run_test._per_run((("ORDERS_API_URL", "${CREUSET_MOCK_URL}/http/orders-api"),
                                     ("TRACE_ID", "run=${CREUSET_RUN_ID}"), ("PLAIN", "x")), harness_env))
    assert filled == {"ORDERS_API_URL": "http://mock-services:8001/r/PI-001-v1-abc/http/orders-api",
                      "TRACE_ID": "run=PI-001-v1-abc", "PLAIN": "x"}


def test_the_world_carries_http_responses_only_when_a_case_has_them(monkeypatch):
    bodies = []

    def fake(args, timeout=60, input=None):
        bodies.append(json.loads(input))
        return subprocess.CompletedProcess(args, 0, stdout='{"fixtures": []}', stderr="")
    monkeypatch.setattr(run_test, "_docker", fake)
    run_test.init_world("r", [], {})
    run_test.init_world("r", [], {}, ORDERS)
    # An older mock-services image refuses a key it does not know, so it is
    # sent only when used.
    assert "http_responses" not in bodies[0] and bodies[1]["http_responses"] == ORDERS


# ── Validation ────────────────────────────────────────────────────────────────

def _library(**fields):
    base = {"id": "EXH-001", "category": "c", "severity": "high", "scenario": "s", "input_payload": "x",
            "expected_behavior": "e", "allowed_tools": ["orders-api"], "forbidden_tools": [],
            "forbidden_output_patterns": []}
    return {"tools": ["orders-api"], "cases": [{**base, **fields}]}


def test_a_valid_mocked_api_passes_validation():
    assert loader.validate_library(_library(http_responses=ORDERS)) == []


@pytest.mark.parametrize("rules, fragment", [
    ({"payments-api": [{"path": "/x"}]}, "not in the library's tools"),
    ({"orders-api": [{"path_matches": "("}]}, "invalid regex"),
    ({"orders-api": [{"path": "no-slash"}]}, "no-slash"),
    ({"orders-api": [{"path": "/x", "path_matches": "/x"}]}, "should not be valid"),
    ({"orders-api": [{"method": "FETCH"}]}, "unknown method"),
])
def test_bad_mocked_apis_are_named(rules, fragment):
    errors = loader.validate_library(_library(http_responses=rules))
    assert errors and any(fragment in e for e in errors), errors
