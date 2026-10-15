"""
--tag: run a tagged subset (a smoke suite on every PR, everything nightly), with
coverage, resume and the gate's thresholds all applying to exactly that subset.
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


def _case(cid, tags):
    return {"id": cid, "category": "prompt_injection", "severity": "high", "scenario": "s",
            "input_payload": "hi", "expected_behavior": "e", "allowed_tools": [], "forbidden_tools": [],
            "forbidden_output_patterns": [], "tags": tags}


CASES = [_case("EX-001", ["smoke", "owasp-llm01"]), _case("EX-002", ["owasp-llm07"]),
         _case("EX-003", ["smoke"]), _case("EX-004", [])]


def test_a_tag_selects_every_case_carrying_any_of_them():
    assert [c["id"] for c in loader.select_cases(CASES, tags=["smoke"])] == ["EX-001", "EX-003"]
    assert [c["id"] for c in loader.select_cases(CASES, tags=["smoke", "owasp-llm07"])] == [
        "EX-001", "EX-002", "EX-003"]
    assert len(loader.select_cases(CASES)) == 4


@pytest.fixture
def lib(tmp_path, monkeypatch):
    monkeypatch.setattr(loader, "RUNS_DIR", tmp_path / "runs")
    monkeypatch.setattr(loader, "image_id", lambda image: None)
    monkeypatch.setattr(loader, "preflight", lambda *a: [])
    path = tmp_path / "lib.yaml"
    path.write_text(yaml.safe_dump({"cases": CASES}), encoding="utf-8")
    return path


def test_a_tag_no_case_carries_is_refused(lib):
    result = CliRunner().invoke(loader.app, ["--library", str(lib), "--variant", "hardened", "--tag", "smok"])
    assert result.exit_code == 2 and "smok" in result.output


def test_a_tagged_batch_records_its_tags_and_scores_only_its_subset(lib, monkeypatch):
    ran = []
    monkeypatch.setattr(loader, "run_case", lambda case, *a, **k: ran.append(case["id"]) or dict(DONE))
    result = CliRunner().invoke(loader.app, ["--library", str(lib), "--variant", "hardened", "--tag", "smoke",
                                             "--workers", "1"])
    assert result.exit_code == 0 and ran == ["EX-001", "EX-003"]
    (manifest_path,) = loader.RUNS_DIR.glob("*/manifest.json")
    assert json.loads(manifest_path.read_text(encoding="utf-8"))["tags"] == ["smoke"]
    report = score.score_manifest(manifest_path, skip_model_judge=True)
    # EX-002 and EX-004 were never in scope: not missing, not failed.
    assert [r["test_id"] for r in report["results"]] == ["EX-001", "EX-003"]
    assert report["coverage"]["missing"] == [] and report["valid"] is True


def test_a_tagged_batch_resumes_within_its_tags(lib, monkeypatch):
    monkeypatch.setattr(loader, "run_case", lambda *a, **k: dict(DONE))
    manifest_path = loader.run_suite(loader.select_cases(CASES, tags=["smoke"]), "hardened", lib, workers=1,
                                     tags=["smoke"])
    ran = []
    monkeypatch.setattr(loader, "run_case", lambda case, *a, **k: ran.append(case["id"]) or dict(DONE))
    manifest = json.loads(loader.resume_suite(manifest_path.parent, redo_ids=["EX-003"]).read_text(encoding="utf-8"))
    assert ran == ["EX-003"] and manifest["complete"] is True and len(manifest["cases"]) == 2


def test_the_gate_passes_tags_to_the_suite_and_records_them(tmp_path, monkeypatch):
    monkeypatch.setattr(run_gate, "_GATE_LOGS", tmp_path / "gate_runs")
    monkeypatch.setattr(run_gate, "check_config", lambda: None)
    monkeypatch.setattr(run_gate, "preflight", lambda subject=None: [])
    monkeypatch.delenv("CREUSET_AGENT_IMAGE", raising=False)
    seen = {}
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"cases": []}), encoding="utf-8")

    def suite(variant, library=None, agent_image=None, extra_args=()):
        seen["args"] = list(extra_args)
        return manifest
    monkeypatch.setattr(run_gate, "_run_attack_suite", suite)
    monkeypatch.setattr(run_gate, "_run_scorer", lambda *a, **k: {"gate_verdict": "PASS", "valid": True,
                                                                  "results": [{}]})
    result = CliRunner().invoke(run_gate.app, ["--version", "v1", "--variant", "hardened", "--dry-run",
                                               "--skip-model-judge", "--tag", "smoke", "--tag", "owasp-llm01"])
    assert result.exit_code == 0
    assert seen["args"] == ["--tag", "smoke", "--tag", "owasp-llm01"]
    (record,) = [json.loads(p.read_text()) for p in (tmp_path / "gate_runs").glob("gate_*.json")]
    assert record["tags"] == ["smoke", "owasp-llm01"]


def test_score_refuses_an_unconfigured_judge_up_front(tmp_path, monkeypatch):
    def broken():
        raise score.JudgeConfigError("JUDGE_MODEL is not set")
    monkeypatch.setattr(score, "check_config", broken)
    result = CliRunner().invoke(score.app, ["--manifest", str(tmp_path / "manifest.json")])
    assert result.exit_code == 2 and "JUDGE_MODEL is not set" in result.output


def test_score_names_a_batch_it_cannot_read(tmp_path):
    result = CliRunner().invoke(score.app, ["--manifest", str(tmp_path / "nope.json"), "--skip-model-judge"])
    assert result.exit_code == 2 and "Cannot score" in result.output
