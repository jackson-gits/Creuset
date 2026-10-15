"""
The circuit breaker and the exit codes that say a run is not a measurement.

A batch whose provider quota is gone, whose key is wrong, or whose agent image
is broken fails every case the same way. Run to the end, that wastes the run
and reads downstream as a perfect detection rate (every failure fails closed).
"""

import json

import pytest
import yaml
from typer.testing import CliRunner

import loader
import run_gate
import score

DONE = {"status": "completed", "output": "ok", "tool_calls": [], "steps": [], "service_audit": [],
        "llm_calls_made": 1, "llm_calls_limit": 15, "budget_ok": True}


def failed(status="error", error="", stderr=""):
    return {"status": status, "error": error, "stderr": stderr, "output": "", "tool_calls": []}


@pytest.mark.parametrize("transcript, expected", [
    (failed(error="RateLimitError: Error code: 429 - tokens per day"), "quota"),
    (failed(error="openai.AuthenticationError: Error code: 401 - invalid_api_key"), "auth"),
    (failed("container_error", "exit=1", stderr="anthropic.AuthenticationError: 401 Unauthorized"), "auth"),
    (failed(error="NotFoundError: Error code: 404 - model_not_found"), "not_found"),
    (failed(error="PermissionDeniedError: Error code: 403"), "forbidden"),
    (failed(error="APIConnectionError: Connection error."), "connection"),
    (failed(error="InternalServerError: Error code: 502 Bad Gateway"), "connection"),
    (failed("parse_error", "No JSON transcript on stdout."), "parse_error"),
    (failed("contract_error", "Transcript breaks schemas/transcript.v1.json"), "contract_error"),
    (failed("timeout", "Container exceeded 180s and was killed."), "timeout"),
    # A traceback's line numbers are not status codes.
    (failed(error='File "agent.py", line 401, in main\nValueError: bad input'), None),
    (dict(DONE), None),
])
def test_failures_are_classed_by_what_would_fail_every_case(transcript, expected):
    assert loader.classify_error(transcript) == expected


def test_the_breaker_trips_on_one_class_in_a_row_only():
    breaker = loader._Breaker()
    auth = failed(error="Error code: 401")
    assert [breaker.record(t) for t in (auth, auth, dict(DONE), auth, auth)] == [None] * 5
    assert breaker.record(auth) == "auth" and breaker.count == 3
    other = loader._Breaker()
    assert [other.record(t) for t in (auth, failed("timeout"), auth)] == [None] * 3


def test_quota_keeps_its_own_threshold(monkeypatch):
    monkeypatch.setattr(loader, "_QUOTA_BREAKER", 2)
    monkeypatch.setattr(loader, "_ERROR_BREAKER", 5)
    breaker = loader._Breaker()
    quota = failed(error="Error code: 429")
    assert breaker.record(quota) is None and breaker.record(quota) == "quota"


CASES = [{"id": f"EX-00{n}", "category": "prompt_injection", "severity": "high", "scenario": "s",
          "input_payload": "hi", "expected_behavior": "e", "allowed_tools": [], "forbidden_tools": [],
          "forbidden_output_patterns": []} for n in range(1, 7)]


@pytest.fixture
def lib(tmp_path, monkeypatch):
    monkeypatch.setattr(loader, "RUNS_DIR", tmp_path / "runs")
    monkeypatch.setattr(loader, "image_id", lambda image: None)
    path = tmp_path / "lib.yaml"
    path.write_text(yaml.safe_dump({"cases": CASES}), encoding="utf-8")
    return path


def test_a_broken_image_stops_the_batch_after_three_runs(lib, monkeypatch):
    calls = []
    monkeypatch.setattr(loader, "run_case", lambda case, *a, **k: calls.append(case["id"]) or failed(
        "parse_error", "No JSON transcript on stdout."))
    manifest = json.loads(loader.run_suite(CASES, "hardened", lib, workers=1).read_text(encoding="utf-8"))
    assert calls == ["EX-001", "EX-002", "EX-003"]
    assert manifest["complete"] is False
    assert manifest["stopped"] == {"reason": "circuit_breaker", "error_class": "parse_error", "consecutive": 3}


def test_an_incomplete_batch_exits_3(lib, monkeypatch):
    monkeypatch.setattr(loader, "preflight", lambda *a: [])
    monkeypatch.setattr(loader, "run_case", lambda *a, **k: failed(error="Error code: 401"))
    result = CliRunner().invoke(loader.app, ["--library", str(lib), "--variant", "hardened", "--workers", "1"])
    assert result.exit_code == loader.EXIT_INCOMPLETE == 3
    assert "Check LLM_API_KEY" in result.output


def test_a_complete_batch_exits_0_whatever_the_agent_did(lib, monkeypatch):
    monkeypatch.setattr(loader, "preflight", lambda *a: [])
    monkeypatch.setattr(loader, "run_case", lambda *a, **k: dict(DONE))
    result = CliRunner().invoke(loader.app, ["--library", str(lib), "--variant", "hardened", "--workers", "1"])
    assert result.exit_code == 0


# ── score.py and the gate ─────────────────────────────────────────────────────

def _batch(tmp_path, transcripts):
    lib = tmp_path / "cases.yaml"
    lib.write_text(yaml.safe_dump({"cases": CASES[:len(transcripts)]}), encoding="utf-8")
    entries = []
    for case, transcript in zip(CASES, transcripts):
        (tmp_path / f"{case['id']}.json").write_text(json.dumps(transcript), encoding="utf-8")
        entries.append({"id": case["id"], "status": transcript["status"], "transcript": f"{case['id']}.json"})
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"library": str(lib), "complete": True, "cases": entries}), encoding="utf-8")
    return manifest


def test_an_invalid_pass_does_not_exit_0(tmp_path, monkeypatch):
    # One fail-closed harness failure in 20 high cases still meets a 95% threshold.
    monkeypatch.setitem(score.THRESHOLDS, "high", 0.5)
    manifest = _batch(tmp_path, [dict(DONE), failed("timeout", "Container exceeded 180s")])
    result = CliRunner().invoke(score.app, ["--manifest", str(manifest), "--output", str(tmp_path / "r.json"),
                                            "--skip-model-judge"])
    report = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert report["gate_verdict"] == "PASS" and report["valid"] is False
    assert result.exit_code == score.EXIT_NOT_MEASURED == 3


def test_a_valid_pass_exits_0(tmp_path):
    manifest = _batch(tmp_path, [dict(DONE)])
    result = CliRunner().invoke(score.app, ["--manifest", str(manifest), "--output", str(tmp_path / "r.json"),
                                            "--skip-model-judge"])
    assert result.exit_code == 0


def _loader(tmp_path, returncode):
    """Plays attacks/loader.py: makes a batch, names it in --manifest-out, exits `returncode`."""
    manifest = tmp_path / "runs" / "b" / "manifest.json"

    def run(cmd):
        manifest.parent.mkdir(parents=True)
        manifest.write_text("{}", encoding="utf-8")
        out = cmd[cmd.index("--manifest-out") + 1]
        with open(out, "w", encoding="utf-8") as f:
            f.write(str(manifest))
        return returncode
    return run, manifest


def test_the_gate_still_scores_a_batch_that_stopped_early(tmp_path, monkeypatch):
    loader_that_stopped, manifest = _loader(tmp_path, 3)
    monkeypatch.setattr(run_gate, "_child", loader_that_stopped)
    assert run_gate._run_attack_suite("hardened") == manifest


def test_an_interrupted_loader_tells_the_gate_its_batch(tmp_path, monkeypatch):
    loader_that_was_stopped, manifest = _loader(tmp_path, 130)
    monkeypatch.setattr(run_gate, "_child", loader_that_was_stopped)
    with pytest.raises(run_gate.SuiteInterrupted) as stop:
        run_gate._run_attack_suite("hardened")
    assert stop.value.manifest == manifest


def test_a_loader_that_names_no_batch_is_a_failed_suite(monkeypatch):
    monkeypatch.setattr(run_gate, "_child", lambda cmd: 0)
    assert run_gate._run_attack_suite("hardened") is None


def test_the_loader_names_its_batch_before_the_first_run(tmp_path, monkeypatch):
    monkeypatch.setattr(loader, "RUNS_DIR", tmp_path / "runs")
    monkeypatch.setattr(loader, "image_id", lambda image: None)
    out = tmp_path / "out" / "manifest-path"
    seen = []
    monkeypatch.setattr(loader, "run_case", lambda *a, **k: seen.append(out.read_text(encoding="utf-8"))
                        or dict(DONE))
    lib = tmp_path / "lib.yaml"
    lib.write_text(yaml.safe_dump({"cases": CASES[:1]}), encoding="utf-8")
    manifest_path = loader.run_suite(CASES[:1], "hardened", lib, workers=1, manifest_out=out)
    assert seen == [str(manifest_path.resolve())]
