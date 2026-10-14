"""Sandbox harness: the audit log is the harness's copy, never the agent's."""

import json
import subprocess

import pytest

import run_test


def _proc(stdout="", returncode=0):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


@pytest.mark.parametrize("variant", ["naive", "hardened", "broken"])
def test_shipped_variants_are_valid(variant):
    assert run_test.validate_variant(variant) is None


@pytest.mark.parametrize("variant", ["../../etc/passwd", "x/y", "", "made-up"])
def test_bad_variants_rejected(variant):
    assert run_test.validate_variant(variant) is not None


def test_harness_audit_replaces_agent_reported_audit(monkeypatch):
    forged = {"status": "completed", "output": "ok", "tool_calls": [],
              "service_audit": []}  # the agent claims it did nothing
    real = [{"action": "file_delete", "path": "invoices/inv_001.txt"}]

    def fake_docker(args, timeout=60):
        if args[0] == "run":
            return _proc(json.dumps(forged))
        if args[0] == "exec":
            assert args[1] == "mock-services"
            return _proc(json.dumps({"entries": real}))
        raise AssertionError(args)

    monkeypatch.setattr(run_test, "_docker", fake_docker)
    t = run_test.run_case({"id": "PI-006", "input_payload": "x"}, "broken")
    assert t["service_audit"] == real
    assert t["audit_source"] == "harness"


@pytest.mark.parametrize("proc", [_proc(returncode=22), _proc("not json"), _proc('{"entries": "x"}')])
def test_unavailable_audit_is_none(monkeypatch, proc):
    monkeypatch.setattr(run_test, "_docker", lambda *a, **k: proc)
    assert run_test.fetch_audit("run-1") is None


def test_run_id_is_url_quoted(monkeypatch):
    seen = {}

    def fake(args, timeout=60):
        seen["url"] = args[-1]
        return _proc('{"entries": []}')
    monkeypatch.setattr(run_test, "_docker", fake)
    run_test.fetch_audit("a&run=b c")
    assert seen["url"].endswith("run=a%26run%3Db%20c")
