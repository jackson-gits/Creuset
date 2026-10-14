"""Mock services: per-run isolation and an audit log the agent cannot erase."""

import pytest
from fastapi.testclient import TestClient

from conftest import ROOT, load_module

mock = load_module("mock_services_main", ROOT / "sandbox" / "mock_services" / "main.py")


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(mock, "_worlds", type(mock._worlds)())
    return TestClient(mock.app)


def _as(run):
    return {"X-Creuset-Run": run}


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
