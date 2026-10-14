"""Deploy path: nothing unvalidated reaches a slot's env file or live traffic."""

import json

import pytest
from typer.testing import CliRunner

import run_gate
import switch

runner = CliRunner()


@pytest.fixture
def state_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(switch, "_STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(switch, "_STATE_FILE", tmp_path / "state" / "state.json")
    monkeypatch.setattr(switch, "_LEGACY_STATE_FILE", tmp_path / "legacy.json")
    monkeypatch.setattr(switch, "_GATE_LOGS", tmp_path / "gate_runs")
    return tmp_path / "state"


@pytest.mark.parametrize("version", ["v1.2.3", "naive", "3f2a9c1d4e5b", "release/2026.10+build-7"])
def test_valid_versions(version):
    assert switch.validate_build(version, "hardened") is None


@pytest.mark.parametrize("version", [
    "v1\nPYTHONPATH=/tmp",      # env-file injection
    "v1\rAGENT_VARIANT=naive",
    "${LLM_API_KEY}",           # Compose interpolation
    "v1 #comment", "", "-v1", "x" * 129,
])
def test_invalid_versions(version):
    assert switch.validate_build(version, "hardened") is not None


@pytest.mark.parametrize("variant", ["../../etc/passwd", "hardened\n", "hard ened", "nope-not-real"])
def test_invalid_variants(variant):
    assert switch.validate_build("v1", variant) is not None


def test_prepare_refuses_injection_and_writes_nothing(state_dir):
    result = runner.invoke(switch.app, ["prepare", "green", "--version", "v1\nEVIL=1",
                                        "--variant", "hardened"])
    assert result.exit_code == 1
    assert not (state_dir / "green.env").exists()


def test_prepare_switch_rollback_round_trip(state_dir):
    assert runner.invoke(switch.app, ["prepare", "green", "--version", "v2",
                                      "--variant", "hardened"]).exit_code == 0
    assert (state_dir / "green.env").read_text() == "AGENT_VARIANT=hardened\nAGENT_VERSION=v2\n"
    assert runner.invoke(switch.app, ["switch", "green", "--version", "v2",
                                      "--variant", "hardened"]).exit_code == 0
    state = json.loads((state_dir / "state.json").read_text())
    assert state["active"] == "green" and state["previous"] == "blue"

    assert runner.invoke(switch.app, ["rollback"]).exit_code == 0
    state = json.loads((state_dir / "state.json").read_text())
    assert state["active"] == "blue"
    assert state["rolled_back_from"]["version"] == "v2"
    # No temp files left behind by the atomic writes.
    assert sorted(p.name for p in state_dir.iterdir()) == ["green.env", "state.json"]


@pytest.fixture
def gate_env(tmp_path, monkeypatch):
    monkeypatch.setattr(run_gate, "_GATE_LOGS", tmp_path / "gate_runs")
    calls = {"suite": 0, "stage": 0, "switch": 0}

    def suite(_variant, library=None):
        calls["suite"] += 1
        return tmp_path / "manifest.json"
    monkeypatch.setattr(run_gate, "_run_attack_suite", suite)
    monkeypatch.setattr(run_gate, "_stage_green", lambda *a: calls.__setitem__("stage", 1) or True)
    monkeypatch.setattr(run_gate, "_do_switch", lambda *a: calls.__setitem__("switch", 1) or True)
    return tmp_path / "gate_runs", calls


def _records(logs):
    return [json.loads(p.read_text()) for p in sorted(logs.glob("gate_*.json"))]


def test_gate_rejects_bad_version_before_spending_quota(gate_env):
    logs, calls = gate_env
    result = runner.invoke(run_gate.app, ["--version", "v1\nEVIL=1", "--variant", "hardened"])
    assert result.exit_code == 2
    assert calls["suite"] == 0
    (record,) = _records(logs)
    assert record["decision"] == "BLOCKED"


def test_gate_never_deploys_an_invalid_pass(gate_env, monkeypatch):
    logs, calls = gate_env
    monkeypatch.setattr(run_gate, "_run_scorer",
                        lambda *a: {"gate_verdict": "PASS", "valid": False, "results": []})
    result = runner.invoke(run_gate.app, ["--version", "v1", "--variant", "hardened"])
    assert result.exit_code == 1
    assert calls["stage"] == 0 and calls["switch"] == 0
    (record,) = _records(logs)
    assert record["decision"] == "BLOCKED" and record["verdict"] == "FAIL"
    assert "not a valid measurement" in record["error"]


def test_gate_deploys_a_valid_pass(gate_env, monkeypatch):
    logs, calls = gate_env
    monkeypatch.setattr(run_gate, "_run_scorer",
                        lambda *a: {"gate_verdict": "PASS", "valid": True, "results": [{}]})
    result = runner.invoke(run_gate.app, ["--version", "v1", "--variant", "hardened"])
    assert result.exit_code == 0
    assert calls["stage"] == 1 and calls["switch"] == 1
    assert _records(logs)[0]["decision"] == "DEPLOYED"
