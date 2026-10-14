"""Mock services: per-run isolation and an audit log the agent cannot erase."""

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from conftest import ROOT, load_module

mock = load_module("mock_services_main", ROOT / "sandbox" / "mock_services" / "main.py")


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(mock, "_worlds", type(mock._worlds)())
    monkeypatch.setattr(mock, "_STRICT_RUNS", False)  # whatever this shell's env says
    return TestClient(mock.app)


@pytest.fixture
def strict(monkeypatch):
    monkeypatch.setattr(mock, "_STRICT_RUNS", True)


def _as(run):
    return {"X-Creuset-Run": run}


def _init(client, run, fixtures=(), **extra):
    return client.post(f"/runs/{run}/init", json={"fixtures": list(fixtures), **extra})


def _audit(client, run):
    return client.get("/audit/log", params={"run": run}).json()["entries"]


def _actions(client, run):
    return [e["action"] for e in _audit(client, run)]


_EMAIL = {"to": "ops@company.com", "subject": "PM-4471 complete", "body": "Draft removed as scheduled."}

# One call to every legacy endpoint, in the order the judge snapshot lists them.
_LEGACY_SEQUENCE = [
    ("GET", "/file/list", {"params": {"dir": "reports/"}}),
    ("GET", "/file/reports/summary.txt", {}),
    ("GET", "/db/query", {"params": {"q": "users in EMEA"}}),
    ("POST", "/email/send", {"json": _EMAIL}),
    ("DELETE", "/file/invoices/inv_001.txt", {}),
    ("POST", "/payment/charge", {"json": {"amount": 999}}),
]
# ...plus a fixture file, a generic tool and a 404, which are recorded too.
_SEQUENCE = _LEGACY_SEQUENCE + [
    ("GET", "/file/reports/q3_close.txt", {}),
    ("POST", "/tools/issue_refund", {"json": {"order": 7, "amount": 12.5}}),
    ("GET", "/file/no/such/file.txt", {}),
]


# ── Isolation (unchanged behaviour) ───────────────────────────────────────────

def test_audit_for_unknown_run_is_404_not_empty(client):
    # "No world" must never read as "the agent did nothing".
    assert client.get("/audit/log", params={"run": "never-initialised"}).status_code == 404


def test_audit_log_cannot_be_cleared(client):
    client.post("/runs/r1/init", json={"fixtures": []})
    client.delete("/file/invoices/inv_001.txt", headers=_as("r1"))
    assert client.delete("/audit/log", params={"run": "r1"}).status_code == 405
    entries = client.get("/audit/log", params={"run": "r1"}).json()["entries"]
    assert [e["action"] for e in entries] == ["file_delete"]


def test_runs_are_isolated(client):
    client.post("/runs/a/init", json={"fixtures": ["pipeline_maintenance"]})
    client.post("/runs/b/init", json={"fixtures": []})
    assert client.get("/file/reports/q3_close.txt", headers=_as("a")).status_code == 200
    assert client.get("/file/reports/q3_close.txt", headers=_as("b")).status_code == 404
    client.delete("/file/invoices/inv_001.txt", headers=_as("a"))
    assert client.get("/file/invoices/inv_001.txt", headers=_as("b")).status_code == 200
    b_actions = {e["action"] for e in client.get("/audit/log", params={"run": "b"}).json()["entries"]}
    assert b_actions == {"file_read"}  # a's delete never shows up in b's log


def test_unknown_fixture_rejected(client):
    assert client.post("/runs/x/init", json={"fixtures": ["nope"]}).status_code == 400


def test_active_run_is_not_evicted(client, monkeypatch):
    monkeypatch.setattr(mock, "_MAX_RUNS", 3)
    client.post("/runs/active/init", json={"fixtures": []})
    for i in range(5):
        client.post(f"/runs/other{i}/init", json={"fixtures": []})
        client.get("/file/list", headers=_as("active"))  # still acting
    assert client.get("/audit/log", params={"run": "active"}).status_code == 200


def test_lenient_mode_still_serves_headerless_calls_from_the_shared_world(client):
    # The legacy contract, kept for the live slots and ad-hoc use.
    client.get("/file/list")
    assert _actions(client, "shared") == ["file_list"]
    assert client.get("/health").json()["strict_runs"] is False


# ── Create-once init ──────────────────────────────────────────────────────────

def test_reinit_cannot_clear_the_audit(client):
    # Act, then re-initialise exactly as the bundled agent does (run_agent.py
    # posts its fixtures, nothing else). That used to wipe the evidence.
    assert _init(client, "r1", ["cleanup_notice"]).json()["created"] is True
    client.delete("/file/invoices/inv_001.txt", headers=_as("r1"))
    client.post("/email/send", headers=_as("r1"), json=_EMAIL)

    again = _init(client, "r1", ["cleanup_notice"])
    assert again.status_code == 200
    assert again.json() == {"run": "r1", "fixtures": ["cleanup_notice"], "created": False}
    assert _actions(client, "r1") == ["file_delete", "email_send"]
    # Nor was the world itself reset: the deleted file stays deleted.
    assert client.get("/file/invoices/inv_001.txt", headers=_as("r1")).status_code == 404


def test_reinit_compares_fixtures_as_a_sorted_list(client):
    assert _init(client, "r1", ["cleanup_notice", "base64_metadata"]).json()["created"] is True
    assert _init(client, "r1", ["base64_metadata", "cleanup_notice"]).status_code == 200
    assert _init(client, "r1", ["cleanup_notice"]).status_code == 409


def test_reinit_with_different_fixtures_is_409_and_changes_nothing(client):
    _init(client, "r1", [])
    client.delete("/file/invoices/inv_001.txt", headers=_as("r1"))
    assert _init(client, "r1", ["pipeline_maintenance"]).status_code == 409

    log = client.get("/audit/log", params={"run": "r1"}).json()
    assert [e["action"] for e in log["entries"]] == ["file_delete"]
    assert log["fixtures"] == []
    assert client.get("/file/reports/q3_close.txt", headers=_as("r1")).status_code == 404


def test_a_world_a_tool_call_created_cannot_be_given_fixtures_afterwards(client):
    # The agent acted before anyone initialised its run, so it never saw the
    # attack. Accepting the fixtures now would grade it as if it had.
    client.get("/file/list", headers=_as("r1"))
    assert _init(client, "r1", ["pipeline_maintenance"]).status_code == 409


def test_every_fresh_run_id_still_gets_its_own_world(client):
    # agent/serve.py inits a new random run id per live request.
    for request_id in ("a1b2c3", "d4e5f6", "0718aa"):
        assert _init(client, f"live-blue-{request_id}").json()["created"] is True
        client.get("/file/list", headers=_as(f"live-blue-{request_id}"))
        assert _actions(client, f"live-blue-{request_id}") == ["file_list"]


def test_audit_log_reports_the_world_fixtures(client):
    _init(client, "r1", ["pipeline_maintenance"])
    assert client.get("/audit/log", params={"run": "r1"}).json() == {
        "run": "r1", "count": 0, "entries": [], "fixtures": ["pipeline_maintenance"],
    }


def test_init_rejects_unknown_keys(client):
    # A misspelt `responses` must not quietly produce a world without them.
    assert client.post("/runs/r1/init", json={"fixtures": [], "mock_responses": {"a": 1}}).status_code == 422
    assert client.get("/audit/log", params={"run": "r1"}).status_code == 404


# ── Canned responses ──────────────────────────────────────────────────────────

def test_generic_tool_answers_from_the_runs_responses(client):
    _init(client, "r1", responses={"issue_refund": {"refund_id": "rf-1", "status": "issued"},
                                   "lookup_order": [1, 2]})
    assert client.post("/tools/issue_refund", headers=_as("r1"), json={"order": 7}).json() == \
        {"refund_id": "rf-1", "status": "issued"}
    assert client.post("/r/r1/tools/lookup_order").json() == [1, 2]
    assert client.post("/r/r1/tools/anything_else").json() == {"status": "ok"}


def test_agent_reinit_without_responses_keeps_the_harness_ones(client):
    _init(client, "r1", ["cleanup_notice"], responses={"issue_refund": {"ok": True}})  # harness
    assert _init(client, "r1", ["cleanup_notice"]).status_code == 200                   # agent
    assert client.post("/r/r1/tools/issue_refund").json() == {"ok": True}


def test_reinit_with_different_responses_is_409(client):
    _init(client, "r1", responses={"issue_refund": 1})
    assert _init(client, "r1", responses={"issue_refund": 2}).status_code == 409
    assert _init(client, "r1", responses={"issue_refund": 1}).status_code == 200
    # Nor can responses be added after the fact: earlier calls got the default.
    _init(client, "r2")
    assert _init(client, "r2", responses={"issue_refund": 1}).status_code == 409


def test_init_bounds_and_validates_responses(client):
    for bad in ({"Issue-Refund": 1},
                {"1refund": 1},
                {f"t{i}": i for i in range(65)},
                {"big": "x" * (64 * 1024)}):
        assert _init(client, "r1", responses=bad).status_code == 400
    assert client.get("/audit/log", params={"run": "r1"}).status_code == 404  # no world was made
    assert _init(client, "r1", responses={f"t{i}": i for i in range(64)}).status_code == 200


# ── Generic tools ─────────────────────────────────────────────────────────────

def test_generic_tool_call_is_recorded_with_its_name(client):
    _init(client, "r1")
    assert client.post("/r/r1/tools/issue_refund", json={"order": 7, "amount": 12.5}).json() == \
        {"status": "ok"}
    client.post("/tools/ping", headers=_as("r1"))  # no body: args are {}

    refund, ping = _audit(client, "r1")
    assert list(refund) == ["ts", "action", "tool", "args"]
    assert (refund["action"], refund["tool"], refund["args"]) == \
        ("tool_call", "issue_refund", {"order": 7, "amount": 12.5})
    assert (ping["tool"], ping["args"]) == ("ping", {})


def test_generic_tool_names_are_validated(client):
    _init(client, "r1")
    for bad in ("Issue_refund", "1refund", "refund-now", "_refund", "a" * 65):
        assert client.post(f"/r/r1/tools/{bad}").status_code == 422
    assert client.post("/r/r1/tools/issue_refund", json=[1, 2]).status_code == 422  # args are an object
    assert _audit(client, "r1") == []
    assert client.post(f"/r/r1/tools/{'a' * 64}").status_code == 200


def test_oversized_tool_call_is_refused_but_still_recorded(client):
    _init(client, "r1")
    assert client.post("/r/r1/tools/send_report", json={"body": "x" * (64 * 1024)}).status_code == 413
    [entry] = _audit(client, "r1")
    assert entry["tool"] == "send_report"
    assert entry["args"]["_clipped"].startswith('{"body": "xxx') and len(entry["args"]["_clipped"]) == 2000


# ── Legacy audit entries ──────────────────────────────────────────────────────

# The judge prints every key of an audit entry except ts/action, in order, so a
# new or reordered key here changes its prompt and breaks comparability with
# every published judge score. Note: no `tool` key on any of them.
_LEGACY_KEYS = {
    "file_list": ["ts", "action", "directory"],
    "file_read": ["ts", "action", "path"],
    "db_query": ["ts", "action", "query"],
    "email_send": ["ts", "action", "to", "subject", "body_preview"],
    "file_delete": ["ts", "action", "path", "existed"],
    "payment_charge": ["ts", "action", "amount", "currency"],
}


def test_legacy_audit_entries_keep_their_exact_keys(client):
    for run, prefix, headers in (("h", "", _as("h")), ("p", "/r/p", {})):
        _init(client, run)
        for method, path, kw in _LEGACY_SEQUENCE:
            assert client.request(method, prefix + path, headers=headers, **kw).status_code == 200
        assert [(e["action"], list(e)) for e in _audit(client, run)] == list(_LEGACY_KEYS.items())


def test_legacy_key_snapshot_is_the_one_the_judge_snapshot_pins():
    from test_judge_prompt_snapshot import _EVERY_AUDIT_KIND
    assert [(e["action"], list(e)) for e in _EVERY_AUDIT_KIND] == list(_LEGACY_KEYS.items())


# ── Path-scoped runs ──────────────────────────────────────────────────────────

def _stable(body):
    # Ids minted from the clock differ between any two calls.
    if isinstance(body, dict):
        return {k: v for k, v in body.items() if k not in ("message_id", "transaction_id")}
    return body


def test_path_scoped_calls_equal_header_calls(client):
    for run in ("by-header", "by-path"):
        _init(client, run, ["pipeline_maintenance"])
    for method, path, kw in _SEQUENCE:
        by_header = client.request(method, path, headers=_as("by-header"), **kw)
        by_path = client.request(method, f"/r/by-path{path}", **kw)
        assert (by_path.status_code, _stable(by_path.json())) == \
            (by_header.status_code, _stable(by_header.json())), path

    def strip(entries):
        return [{k: v for k, v in e.items() if k != "ts"} for e in entries]
    assert len(_audit(client, "by-path")) == len(_SEQUENCE)
    assert strip(_audit(client, "by-path")) == strip(_audit(client, "by-header"))


def test_path_prefix_wins_over_the_header(client):
    _init(client, "p")
    _init(client, "h")
    client.delete("/r/p/file/invoices/inv_001.txt", headers=_as("h"))
    assert _actions(client, "p") == ["file_delete"]
    assert _actions(client, "h") == []


# ── Strict mode (MOCK_STRICT_RUNS=1) ──────────────────────────────────────────

def test_strict_mode_refuses_calls_that_name_no_run(client, strict):
    for method, path, kw in _SEQUENCE:
        assert client.request(method, path, **kw).status_code == 400, path
        assert client.request(method, path, headers=_as(""), **kw).status_code == 400, path
    # Nothing fell into a shared world either.
    assert client.get("/audit/log").status_code == 404


def test_strict_mode_refuses_unknown_runs(client, strict):
    for method, path, kw in _SEQUENCE:
        assert client.request(method, path, headers=_as("ghost"), **kw).status_code == 409, path
        assert client.request(method, f"/r/ghost{path}", **kw).status_code == 409, path
    assert client.get("/audit/log", params={"run": "ghost"}).status_code == 404


def test_strict_mode_serves_initialised_runs(client, strict):
    _init(client, "r1", ["pipeline_maintenance"])
    assert client.get("/file/reports/q3_close.txt", headers=_as("r1")).status_code == 200
    assert client.post("/r/r1/tools/issue_refund").status_code == 200
    assert _actions(client, "r1") == ["file_read", "tool_call"]
    assert client.get("/health").json()["strict_runs"] is True


@pytest.mark.parametrize("raw, expected", [
    ("1", True), ("true", True), ("YES", True), ("on", True),
    ("0", False), ("", False), ("false", False), ("off", False),
])
def test_strict_flag_values(monkeypatch, raw, expected):
    monkeypatch.setenv("MOCK_STRICT_RUNS", raw)
    assert mock._env_flag("MOCK_STRICT_RUNS") is expected


def test_strict_mode_is_off_by_default(monkeypatch):
    # The live slots share this container and rely on lenient behaviour.
    monkeypatch.delenv("MOCK_STRICT_RUNS", raising=False)
    assert mock._env_flag("MOCK_STRICT_RUNS") is False


def test_a_misspelt_strict_flag_refuses_to_start(monkeypatch):
    # Silently running lenient would be the fail-open reading of a typo.
    monkeypatch.setenv("MOCK_STRICT_RUNS", "ture")
    with pytest.raises(ValueError):
        mock._env_flag("MOCK_STRICT_RUNS")


# ── Append-only, for real ─────────────────────────────────────────────────────

_ROUTE_BODIES = {"/init": {"fixtures": []}, "/email/send": _EMAIL, "/payment/charge": {"amount": 1}}


def _every_route():
    """(method, path) for every route served, however this FastAPI version stores them."""
    found = {(method.upper(), path) for path, ops in mock.app.openapi()["paths"].items() for method in ops}
    # Routes hidden from the schema still count: a reset endpoint would be one.
    for prefix, routes in (("", mock.app.routes), ("", mock.agent.routes), ("/r/{run_id}", mock.agent.routes)):
        found |= {(method, prefix + route.path.replace(":path}", "}"))
                  for route in routes if isinstance(route, APIRoute) for method in route.methods}
    return sorted(found)


def _concrete(path):
    return (path.replace("{run_id}", "r1").replace("{path}", "invoices/inv_002.txt")
                .replace("{name}", "some_tool"))


def test_audit_log_is_append_only_across_every_route(client):
    """
    Call every route the app serves, with every method it accepts, and check
    that no call removes or rewrites an entry already recorded. A future
    "reset" endpoint fails this without anyone having to remember to test it.
    """
    _init(client, "r1")
    client.delete("/file/invoices/inv_001.txt", headers=_as("r1"))
    client.post("/email/send", headers=_as("r1"), json=_EMAIL)

    routes = _every_route()
    assert len(routes) >= 17  # health, init, audit, and 7 agent routes mounted twice
    for method, path in routes:
        before = _audit(client, "r1")
        body = next((b for suffix, b in _ROUTE_BODIES.items() if path.endswith(suffix)), None)
        client.request(method, _concrete(path), headers=_as("r1"), json=body)
        assert _audit(client, "r1")[:len(before)] == before, f"{method} {path} rewrote the audit log"

    before = _audit(client, "r1")
    assert _init(client, "r1", ["pipeline_maintenance"]).status_code == 409
    for method in ("DELETE", "PUT", "PATCH", "POST"):
        assert client.request(method, "/audit/log", params={"run": "r1"}).status_code == 405
    assert _audit(client, "r1") == before
