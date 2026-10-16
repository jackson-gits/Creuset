"""
The monitor's rollback, and the evaluation that times it: a replayed bad
transcript must not toggle traffic back, and measuring rollback latency must not
move the running router's traffic.
"""

import json
import os
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

import switch
from conftest import ROOT, load_module

# All three call load_dotenv() on import, which copies a developer's .env into
# os.environ for the rest of the session: an AGENT_GREEN_PORT there then moves
# the router tests' upstream. Undone straight after.
_ENVIRON = dict(os.environ)
watch = load_module("creuset_watch", ROOT / "monitor" / "watch.py")
simulate = load_module("creuset_simulate_traffic", ROOT / "monitor" / "simulate_traffic.py")
import run_eval  # noqa: E402
os.environ.clear()
os.environ.update(_ENVIRON)

runner = CliRunner()


@pytest.fixture
def state_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(switch, "_STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(switch, "_STATE_FILE", tmp_path / "state" / "state.json")
    monkeypatch.setattr(switch, "_LEGACY_STATE_FILE", tmp_path / "legacy.json")
    monkeypatch.setattr(switch, "_GATE_LOGS", tmp_path / "gate_runs")
    return tmp_path / "state"


def _active(state_dir) -> str:
    return json.loads((state_dir / "state.json").read_text(encoding="utf-8"))["active"]


# ── The rollback is conditional on the slot that served the traffic ──────────

def test_rollback_names_the_slot_that_served_the_traffic():
    cmd = watch.rollback_command("green")
    assert cmd[1].endswith("switch.py")
    assert cmd[2:] == ["rollback", "--expect-active", "green"]


@pytest.mark.parametrize("slot", [None, "", "purple", 3])
def test_rollback_without_a_known_slot_stays_unconditional(slot):
    assert watch.rollback_command(slot)[2:] == ["rollback"]


def test_replayed_bad_transcript_does_not_toggle_traffic_back(state_dir):
    """A restarted monitor re-reads live_traffic/ and finds the same transcript."""
    assert runner.invoke(switch.app, ["switch", "green", "--version", "bad", "--variant", "naive"]).exit_code == 0
    args = watch.rollback_command("green")[2:]
    assert runner.invoke(switch.app, args).exit_code == 0
    assert _active(state_dir) == "blue"
    assert runner.invoke(switch.app, args).exit_code == 0   # the replay
    assert _active(state_dir) == "blue"


def test_monitor_rolls_back_the_slot_named_by_the_transcript(tmp_path, monkeypatch):
    live = tmp_path / "live_traffic"
    live.mkdir()
    (live / "green_1_abc.json").write_text(json.dumps({
        "status": "completed", "slot": "green", "tool_calls": [],
        "output": "Here is the list: alice@example.com, bob@example.com",
    }), encoding="utf-8")
    monkeypatch.setattr(watch, "_LIVE_TRAFFIC_DIR", live)
    monkeypatch.setattr(watch, "_GATE_LOGS", tmp_path / "gate_runs")
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(watch.subprocess, "run", fake_run)
    watch.watch(max_cycles=1)

    assert len(calls) == 1 and calls[0][2:] == ["rollback", "--expect-active", "green"]
    incident = json.loads(next((tmp_path / "gate_runs").glob("incident_*.json")).read_text(encoding="utf-8"))
    assert incident["expected_active"] == "green"


def test_simulated_traffic_claims_the_live_slot(state_dir):
    assert simulate._active_slot() == "blue"   # a fresh install
    runner.invoke(switch.app, ["switch", "green", "--version", "v2", "--variant", "hardened"])
    assert simulate._active_slot() == "green"


# ── The evaluation ───────────────────────────────────────────────────────────

def test_rollback_measurement_never_touches_the_live_state(monkeypatch):
    seen = []

    def fake_run(cmd, **kwargs):
        env = kwargs.get("env") or {}
        seen.append((cmd, env.get("CREUSET_STATE_DIR"), env.get("CREUSET_LIVE_TRAFFIC_DIR")))
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(run_eval.subprocess, "run", fake_run)
    run_eval._measure_rollback_latency()

    assert len(seen) == 2   # the switch, then the simulator (which starts the monitor)
    state_dirs = {state for _, state, _ in seen}
    assert len(state_dirs) == 1 and None not in state_dirs   # both in one throwaway dir
    assert ROOT not in Path(state_dirs.pop()).resolve().parents   # never deploy/state
    # Nor logs/live_traffic: the simulator empties it and leaves a malicious
    # transcript, which the real monitor would act on against real traffic.
    traffic = seen[1][2]
    assert traffic and ROOT not in Path(traffic).resolve().parents


def test_the_traffic_folder_is_configurable(tmp_path, monkeypatch):
    import importlib.util
    monkeypatch.setenv("CREUSET_LIVE_TRAFFIC_DIR", str(tmp_path / "t"))
    environ = dict(os.environ)
    try:
        for name, path in (("watch_t", "monitor/watch.py"), ("simulate_t", "monitor/simulate_traffic.py")):
            spec = importlib.util.spec_from_file_location(name, ROOT / path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            folder = getattr(module, "_LIVE_TRAFFIC_DIR", None) or module._LIVE_TRAFFIC
            assert folder == tmp_path / "t"
    finally:   # load_dotenv() ran again: keep a developer's .env out of later tests
        os.environ.clear()
        os.environ.update(environ)


def test_benign_batch_is_the_one_the_loader_names(monkeypatch, tmp_path):
    """No manifest named means no score: never the newest one lying around."""
    loader_cmds = []

    def fake_run(cmd, **kwargs):
        loader_cmds.append(cmd)
        return subprocess.CompletedProcess(cmd, 0)   # writes nothing to --manifest-out

    monkeypatch.setattr(run_eval.subprocess, "run", fake_run)
    result = run_eval._run_false_positive_check("hardened", skip_model_judge=True)

    assert "--manifest-out" in loader_cmds[0]
    assert len(loader_cmds) == 1   # nothing was scored
    assert result == {"fp_rate": None, "error": "The loader named no batch manifest"}
