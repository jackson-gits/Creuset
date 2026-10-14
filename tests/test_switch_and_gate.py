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


# ── The gate CLI ──────────────────────────────────────────────────────────────

IMAGE = "sha256:" + "a" * 64


def _manifest(tmp_path, ids=(IMAGE,), subject_id=IMAGE):
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"subject": {"kind": "bundled", "image_id": subject_id},
                                "cases": [{"id": f"PI-00{i}", "agent_image_id": x}
                                          for i, x in enumerate(ids, 1)]}))
    return path


@pytest.fixture
def gate_env(tmp_path, monkeypatch):
    monkeypatch.setattr(run_gate, "_GATE_LOGS", tmp_path / "gate_runs")
    calls = {"suite": [], "deploy": []}
    manifest = _manifest(tmp_path)

    def suite(variant, library=None, agent_image=None, extra_args=()):
        calls["suite"].append({"variant": variant, "library": library, "agent_image": agent_image})
        calls["suite_args"] = list(extra_args)
        return manifest
    monkeypatch.setattr(run_gate, "_run_attack_suite", suite)

    def deploy(version, variant, tested):
        calls["deploy"].append(tested)
        return {"ok": True, "slot": "green", "error": None}
    monkeypatch.setattr(run_gate, "_deploy", deploy)
    # An external image from the developer's .env must not leak into these runs,
    # nor whether the developer's .env configures a judge.
    monkeypatch.delenv("CREUSET_AGENT_IMAGE", raising=False)
    monkeypatch.setattr(run_gate, "check_config", lambda: None)
    return tmp_path / "gate_runs", calls


def _records(logs):
    return [json.loads(p.read_text()) for p in sorted(logs.glob("gate_*.json"))]


def _scorer(monkeypatch, verdict="PASS", valid=True):
    monkeypatch.setattr(run_gate, "_run_scorer",
                        lambda *a: {"gate_verdict": verdict, "valid": valid, "results": [{}]})


def test_gate_rejects_bad_version_before_spending_quota(gate_env):
    logs, calls = gate_env
    result = runner.invoke(run_gate.app, ["--version", "v1\nEVIL=1", "--variant", "hardened"])
    assert result.exit_code == 2
    assert calls["suite"] == []
    (record,) = _records(logs)
    assert record["decision"] == "BLOCKED"


def test_gate_never_deploys_an_invalid_pass(gate_env, monkeypatch):
    logs, calls = gate_env
    _scorer(monkeypatch, valid=False)
    result = runner.invoke(run_gate.app, ["--version", "v1", "--variant", "hardened"])
    assert result.exit_code == 1
    assert calls["deploy"] == []
    (record,) = _records(logs)
    assert record["decision"] == "BLOCKED" and record["verdict"] == "FAIL"
    assert "not a valid measurement" in record["error"]


def test_gate_deploys_a_valid_pass_bound_to_the_tested_image(gate_env, monkeypatch):
    logs, calls = gate_env
    _scorer(monkeypatch)
    result = runner.invoke(run_gate.app, ["--version", "v1", "--variant", "hardened"])
    assert result.exit_code == 0
    assert calls["deploy"] == [IMAGE]
    (record,) = _records(logs)
    assert record["decision"] == "DEPLOYED" and record["slot"] == "green"
    assert record["tested_image_id"] == IMAGE


def test_a_failed_deploy_is_not_exit_0(gate_env, monkeypatch):
    """A PASS whose build never went live used to exit 0, so CI reported a deploy."""
    logs, _ = gate_env
    _scorer(monkeypatch)
    monkeypatch.setattr(run_gate, "_deploy",
                        lambda *a: {"ok": False, "slot": "blue", "error": "slot unhealthy"})
    result = runner.invoke(run_gate.app, ["--version", "v1", "--variant", "hardened"])
    assert result.exit_code == 3
    (record,) = _records(logs)
    assert record["verdict"] == "PASS" and record["decision"] == "SWITCH_FAILED"
    assert "slot unhealthy" in record["error"]


def test_a_blocked_gate_exits_1(gate_env, monkeypatch):
    _, calls = gate_env
    _scorer(monkeypatch, verdict="FAIL")
    assert runner.invoke(run_gate.app, ["--version", "v1", "--variant", "hardened"]).exit_code == 1
    assert calls["deploy"] == []


def test_external_image_needs_dry_run(gate_env):
    logs, calls = gate_env
    result = runner.invoke(run_gate.app, ["--version", "1.4.0", "--variant", "v1-4",
                                          "--agent-image", "my-agent:1.4.0"])
    assert result.exit_code == 2 and calls["suite"] == []
    assert "--dry-run" in _records(logs)[0]["error"]


def test_external_image_dry_run_is_gated_and_never_deployed(gate_env, monkeypatch, tmp_path):
    logs, calls = gate_env
    _scorer(monkeypatch)
    lib = tmp_path / "lib.yaml"
    lib.write_text("cases: []\n")
    result = runner.invoke(run_gate.app, ["--version", "1.4.0", "--variant", "v1-4", "--dry-run",
                                          "--agent-image", "my-agent:1.4.0", "--library", str(lib)])
    assert result.exit_code == 0, result.output
    assert calls["suite"] == [{"variant": "v1-4", "library": lib, "agent_image": "my-agent:1.4.0"}]
    assert calls["deploy"] == []
    assert _records(logs)[0]["decision"] == "DRY_RUN_WOULD_DEPLOY"


def test_a_misconfigured_judge_is_rejected_before_spending_agent_quota(gate_env, monkeypatch):
    logs, calls = gate_env

    def broken():
        raise run_gate.JudgeConfigError("JUDGE_MODEL is not set")
    monkeypatch.setattr(run_gate, "check_config", broken)
    result = runner.invoke(run_gate.app, ["--version", "v1", "--variant", "hardened"])
    assert result.exit_code == 2 and calls["suite"] == []
    assert "JUDGE_MODEL" in _records(logs)[0]["error"]
    # Rule-only runs do not need a judge at all.
    _scorer(monkeypatch)
    result = runner.invoke(run_gate.app, ["--version", "v1", "--variant", "hardened", "--skip-model-judge"])
    assert result.exit_code == 0


def test_missing_library_is_rejected_before_running(gate_env, tmp_path):
    _, calls = gate_env
    result = runner.invoke(run_gate.app, ["--version", "v1", "--variant", "hardened",
                                          "--library", str(tmp_path / "nope.yaml")])
    assert result.exit_code == 2 and calls["suite"] == []


@pytest.mark.parametrize("ids, subject_id", [
    ((IMAGE, "sha256:" + "b" * 64), IMAGE),   # a resumed batch that mixed builds
    ((IMAGE, None), IMAGE),                   # a case with no recorded image
    ((IMAGE,), None),                         # the batch never recorded its image
])
def test_tested_image_is_none_unless_the_whole_batch_ran_one_image(tmp_path, ids, subject_id):
    assert run_gate.tested_image_id(_manifest(tmp_path, ids, subject_id)) is None


def test_tested_image_of_a_uniform_batch(tmp_path):
    assert run_gate.tested_image_id(_manifest(tmp_path, (IMAGE, IMAGE))) == IMAGE


# ── _deploy: the inactive slot, the tested bytes ──────────────────────────────

@pytest.fixture
def deploy_env(state_dir, monkeypatch):
    calls = {"stage": [], "switch": []}
    monkeypatch.setattr(run_gate, "image_id", lambda image: IMAGE)
    monkeypatch.setattr(run_gate, "_stage_slot",
                        lambda slot, *a: calls["stage"].append(slot))
    monkeypatch.setattr(run_gate, "_slot_image_id", lambda slot: IMAGE)
    monkeypatch.setattr(run_gate, "_do_switch",
                        lambda slot, *a: calls["switch"].append(slot) or True)
    return calls


@pytest.mark.parametrize("live, expected", [("blue", "green"), ("green", "blue")])
def test_deploy_stages_the_inactive_slot(deploy_env, state_dir, live, expected):
    """Always staging green recreated the LIVE container whenever green was live."""
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "state.json").write_text(json.dumps({"active": live}))
    outcome = run_gate._deploy("v2", "hardened", IMAGE)
    assert outcome == {"ok": True, "slot": expected, "error": None}
    assert deploy_env == {"stage": [expected], "switch": [expected]}


def test_deploy_refuses_a_rebuilt_tag(deploy_env, monkeypatch):
    monkeypatch.setattr(run_gate, "image_id", lambda image: "sha256:" + "c" * 64)
    outcome = run_gate._deploy("v2", "hardened", IMAGE)
    assert not outcome["ok"] and "rebuilt" in outcome["error"]
    assert deploy_env == {"stage": [], "switch": []}


def test_deploy_refuses_an_unknown_tested_image(deploy_env):
    assert not run_gate._deploy("v2", "hardened", None)["ok"]
    assert deploy_env == {"stage": [], "switch": []}


def test_traffic_never_moves_to_a_slot_running_other_bytes(deploy_env, monkeypatch):
    monkeypatch.setattr(run_gate, "_slot_image_id", lambda slot: "sha256:" + "d" * 64)
    outcome = run_gate._deploy("v2", "hardened", IMAGE)
    assert not outcome["ok"] and "not the tested image" in outcome["error"]
    assert deploy_env["stage"] == ["green"] and deploy_env["switch"] == []


def test_deploy_refuses_unreadable_state(deploy_env, state_dir):
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "state.json").write_text("{torn")
    outcome = run_gate._deploy("v2", "hardened", IMAGE)
    assert not outcome["ok"] and outcome["slot"] is None
    assert deploy_env == {"stage": [], "switch": []}


def test_agent_settings_pass_through_to_the_suite(gate_env, monkeypatch, tmp_path):
    _, calls = gate_env
    _scorer(monkeypatch)
    env_file = tmp_path / "agent.env"
    env_file.write_text("REGION=eu\n", encoding="utf-8")
    result = runner.invoke(run_gate.app, ["--version", "v1", "--variant", "hardened", "--dry-run",
                                          "--agent-env", "FEATURE_X=on", "--agent-env-file", str(env_file)])
    assert result.exit_code == 0, result.output
    assert calls["suite_args"] == ["--agent-env", "FEATURE_X=on", "--agent-env-file", str(env_file)]


def test_agent_settings_that_touch_the_contract_are_rejected_up_front(gate_env):
    logs, calls = gate_env
    result = runner.invoke(run_gate.app, ["--version", "v1", "--variant", "hardened", "--dry-run",
                                          "--agent-env", "OPENAI_BASE_URL=http://elsewhere"])
    assert result.exit_code == 2 and calls["suite"] == []
    assert "OPENAI_BASE_URL" in _records(logs)[0]["error"]


def test_repeat_passes_through_and_is_recorded(gate_env, monkeypatch):
    logs, calls = gate_env
    _scorer(monkeypatch)
    result = runner.invoke(run_gate.app, ["--version", "v1", "--variant", "hardened", "--dry-run", "--repeat", "5"])
    assert result.exit_code == 0, result.output
    assert calls["suite_args"][-2:] == ["--repeat", "5"]
    assert _records(logs)[0]["repeat"] == 5
