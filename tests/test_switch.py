"""
Deploy state past the first deploy: no toggle-back rollbacks, no stale live
record, no lost updates between concurrent writers, no overwritten audit events,
and a state dir a demo can point somewhere harmless.
"""

import json
import os
import re
import subprocess
import sys
import threading
import time

import pytest
from typer.testing import CliRunner

import switch
from conftest import ROOT, load_module

runner = CliRunner()
SWITCH_PY = ROOT / "deploy" / "switch.py"


@pytest.fixture
def state_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(switch, "_STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(switch, "_STATE_FILE", tmp_path / "state" / "state.json")
    monkeypatch.setattr(switch, "_LEGACY_STATE_FILE", tmp_path / "legacy.json")
    monkeypatch.setattr(switch, "_GATE_LOGS", tmp_path / "gate_runs")
    return tmp_path / "state"


def _cli(*args):
    return runner.invoke(switch.app, list(args))


def _said(result) -> str:
    """CLI output with rich's line wrapping undone (a long tmp path moves the breaks)."""
    return " ".join(result.output.split())


def _state(state_dir):
    return json.loads((state_dir / "state.json").read_text(encoding="utf-8"))


def _events(state_dir):
    logs = state_dir.parent / "gate_runs"
    return sorted(logs.glob("switch_*.json")) if logs.is_dir() else []


# ── Rollback is conditional ──────────────────────────────────────────────────

def test_double_rollback_with_expect_active_leaves_blue_live(state_dir):
    assert _cli("switch", "green", "--version", "v1", "--variant", "hardened").exit_code == 0
    assert _cli("rollback", "--expect-active", "green").exit_code == 0
    assert _state(state_dir)["active"] == "blue"
    before = (state_dir / "state.json").read_bytes()
    logged = len(_events(state_dir))

    # A second anomaly from the same bad build, or a restarted monitor replaying
    # it, must not send traffic straight back to the slot it was rolled off.
    result = _cli("rollback", "--expect-active", "green")
    assert result.exit_code == 0
    assert "nothing to roll back" in _said(result)
    assert (state_dir / "state.json").read_bytes() == before
    assert len(_events(state_dir)) == logged
    assert _state(state_dir)["active"] == "blue"


def test_plain_rollback_still_toggles(state_dir):
    """The guard is opt-in: existing callers of `rollback` see no change."""
    _cli("switch", "green", "--version", "v1", "--variant", "hardened")
    assert _cli("rollback").exit_code == 0
    assert _cli("rollback").exit_code == 0
    assert _state(state_dir)["active"] == "green"


def test_expect_active_rejects_unknown_slot(state_dir):
    result = _cli("rollback", "--expect-active", "purple")
    assert result.exit_code == 1
    assert not state_dir.exists()


def test_rollback_refuses_a_previous_slot_that_does_not_exist(state_dir):
    state_dir.mkdir()
    (state_dir / "state.json").write_text(json.dumps({"active": "green", "previous": "purple"}))
    result = _cli("rollback")
    assert result.exit_code == 1
    assert "Cannot roll back" in _said(result)
    assert _state(state_dir)["active"] == "green"


# ── A same-slot switch keeps the live record honest ─────────────────────────

def test_same_slot_switch_updates_the_live_build(state_dir):
    assert _cli("switch", "green", "--version", "v1", "--variant", "hardened").exit_code == 0
    result = _cli("switch", "green", "--version", "v2", "--variant", "naive")
    assert result.exit_code == 0
    assert "Already on green" in _said(result)

    state = _state(state_dir)
    assert (state["active"], state["version"], state["variant"]) == ("green", "v2", "naive")
    assert state["slots"]["green"] == {"version": "v2", "variant": "naive"}
    # Traffic did not move, so the rollback target is still the older build.
    assert state["previous"] == "blue"
    assert state["slots"]["blue"]["version"] == "initial"
    assert (state_dir / "green.env").read_text() == "AGENT_VARIANT=naive\nAGENT_VERSION=v2\n"
    assert [json.loads(p.read_text())["event"] for p in _events(state_dir)].count("redeploy") == 1

    assert _cli("rollback").exit_code == 0
    state = _state(state_dir)
    assert (state["active"], state["version"]) == ("blue", "initial")
    assert state["rolled_back_from"] == {"slot": "green", "version": "v2", "variant": "naive"}


def test_switch_without_variant_keeps_the_staged_variant(state_dir):
    # Blue is live running naive; hardened is staged into green.
    _cli("switch", "blue", "--version", "v0", "--variant", "naive")
    _cli("prepare", "green", "--version", "v1", "--variant", "hardened")
    assert _cli("switch", "green", "--version", "v1").exit_code == 0
    state = _state(state_dir)
    # green.env still says hardened, so that is what green runs - not the
    # variant of the slot traffic just left.
    assert state["variant"] == "hardened"
    assert state["slots"]["green"]["variant"] == "hardened"


def test_prepare_into_the_live_slot_warns(state_dir):
    _cli("switch", "green", "--version", "v1", "--variant", "hardened")
    result = _cli("prepare", "green", "--version", "v2", "--variant", "hardened")
    assert result.exit_code == 0
    assert "live slot" in _said(result) and "inactive slot is blue" in _said(result)


# ── load_state / inactive_slot / validate_build ─────────────────────────────

@pytest.mark.parametrize("active, expected", [("blue", "green"), ("green", "blue")])
def test_inactive_slot(active, expected):
    assert switch.inactive_slot({"active": active}) == expected


def test_inactive_slot_treats_missing_active_as_blue_like_the_router():
    assert switch.inactive_slot({}) == "green"


def test_inactive_slot_refuses_unknown_active():
    with pytest.raises(switch.StateError):
        switch.inactive_slot({"active": "purple"})


def test_load_state_default_is_a_fresh_copy(state_dir):
    first = switch.load_state()
    first["slots"]["blue"]["version"] = "mutated"
    assert switch.load_state()["slots"]["blue"]["version"] == "initial"
    assert switch.inactive_slot(switch.load_state()) == "green"


@pytest.mark.parametrize("content", ['{"active": "gre', '["green"]', '{"active": "purple"}',
                                     '{"active": "blue", "slots": []}'])
def test_load_state_refuses_unusable_file(state_dir, content):
    state_dir.mkdir()
    (state_dir / "state.json").write_text(content)
    with pytest.raises(switch.StateError):
        switch.load_state()


@pytest.mark.parametrize("args", [
    ["prepare", "green", "--version", "v1", "--variant", "hardened"],
    ["switch", "green", "--version", "v1", "--variant", "hardened"],
    ["rollback"],
    ["status"],
])
def test_commands_refuse_corrupt_state_and_write_nothing(state_dir, args):
    state_dir.mkdir()
    (state_dir / "state.json").write_text('{"active": "gre')
    result = _cli(*args)
    assert result.exit_code == 1
    assert "refusing to guess" in _said(result)
    assert (state_dir / "state.json").read_text() == '{"active": "gre'
    assert sorted(p.name for p in state_dir.iterdir()) == ["state.json"]


def test_legacy_state_file_is_migrated(state_dir, tmp_path):
    (tmp_path / "legacy.json").write_text(json.dumps(
        {"active": "green", "version": "v0", "variant": "naive"}))
    state = switch.load_state()
    assert state["slots"]["green"] == {"version": "v0", "variant": "naive"}
    assert state["slots"]["blue"] == {"version": "unknown", "variant": None}


def test_external_subject_skips_only_the_variant_file_check():
    assert switch.validate_build("v1", "my-external-agent") is not None
    assert switch.validate_build("v1", "my-external-agent", require_variant_file=False) is None
    # The alphabet still applies: the label is written into files and env.
    assert switch.validate_build("v1", "../x", require_variant_file=False) is not None
    assert switch.validate_build("v1\nX=1", "ext", require_variant_file=False) is not None


# ── Lock ─────────────────────────────────────────────────────────────────────

def test_lock_serialises_concurrent_writers(state_dir):
    """Read-modify-write under the lock loses no update, whatever the interleaving."""
    state_dir.mkdir()
    counter = state_dir / "counter"
    counter.write_text("0")

    def bump():
        for _ in range(5):
            with switch.state_lock(timeout=10):
                n = int(counter.read_text())
                time.sleep(0.002)  # widen the window a lost update needs
                counter.write_text(str(n + 1))

    threads = [threading.Thread(target=bump) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert counter.read_text() == "30"
    assert not (state_dir / ".switch.lock").exists()


def test_lock_excludes_another_process(state_dir):
    """The lock is a file, so it holds across processes - the gate and the monitor."""
    holder = subprocess.Popen(
        [sys.executable, "-c",
         "import sys; sys.path.insert(0, sys.argv[1]); import switch\n"
         "with switch.state_lock():\n"
         "    print('held', flush=True); sys.stdin.read()",
         str(ROOT / "deploy")],
        env={**os.environ, "CREUSET_STATE_DIR": str(state_dir)},
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
    )
    try:
        assert holder.stdout.readline().strip() == "held"
        with pytest.raises(switch.LockTimeout):
            with switch.state_lock(timeout=0.3):
                pass
    finally:
        holder.stdin.close()
        holder.wait(timeout=10)
    with switch.state_lock(timeout=5):
        pass
    assert not (state_dir / ".switch.lock").exists()


def test_held_lock_times_out_cleanly_and_changes_nothing(state_dir, monkeypatch):
    monkeypatch.setattr(switch, "_LOCK_TIMEOUT_SECONDS", 0.2)
    state_dir.mkdir()
    (state_dir / ".switch.lock").write_text("pid 999999\n")
    result = _cli("switch", "green", "--version", "v1", "--variant", "hardened")
    assert result.exit_code == 1
    assert "state lock" in _said(result) and "pid 999999" in _said(result)
    assert sorted(p.name for p in state_dir.iterdir()) == [".switch.lock"]  # not ours to remove


def test_stale_lock_is_broken_with_a_message(state_dir):
    state_dir.mkdir()
    lock = state_dir / ".switch.lock"
    lock.write_text("pid 999999\n")
    old = time.time() - switch._LOCK_STALE_SECONDS - 5
    os.utime(lock, (old, old))
    result = _cli("switch", "green", "--version", "v1", "--variant", "hardened")
    assert result.exit_code == 0
    assert "stale state lock" in _said(result)
    assert _state(state_dir)["active"] == "green"
    assert not lock.exists()


def test_stale_break_rechecks_under_the_breaker(state_dir, monkeypatch):
    """Another waiter replaced the dead lock between our two looks: leave it alone."""
    state_dir.mkdir()
    lock = state_dir / ".switch.lock"
    lock.write_text("pid 1\n")
    ages = iter([switch._LOCK_STALE_SECONDS + 1, 0.01])
    monkeypatch.setattr(switch, "_age", lambda path: next(ages))
    assert switch._break_if_stale(lock) is False
    assert lock.exists()
    assert not (state_dir / ".switch.lock.break").exists()


def test_lock_released_when_the_body_fails(state_dir):
    with pytest.raises(RuntimeError):
        with switch.state_lock():
            raise RuntimeError("boom")
    assert not (state_dir / ".switch.lock").exists()


# ── Audit records ────────────────────────────────────────────────────────────

def test_events_in_the_same_millisecond_get_unique_files(state_dir, monkeypatch):
    monkeypatch.setattr(switch.time, "time", lambda: 1_800_000_000.0)
    for args in (["switch", "green", "--version", "v1", "--variant", "hardened"], ["rollback"],
                 ["switch", "green", "--version", "v2", "--variant", "hardened"], ["rollback"]):
        assert _cli(*args).exit_code == 0

    paths = _events(state_dir)
    assert len(paths) == 4  # second-resolution names used to leave 1
    for path in paths:
        assert re.fullmatch(r"switch_1800000000000_[0-9a-f]{8}\.json", path.name)
        record = json.loads(path.read_text())
        assert path.name == f"switch_{record['id']}.json"
        assert record["ts"] == 1_800_000_000 and record["ts_ms"] == 1_800_000_000_000
    assert sorted(json.loads(p.read_text())["event"] for p in paths) == [
        "rollback", "rollback", "switch", "switch"]


def test_records_name_a_non_default_state_dir(state_dir):
    _cli("switch", "green", "--version", "v1", "--variant", "hardened")
    (path,) = _events(state_dir)
    assert json.loads(path.read_text())["state_dir"] == str(state_dir)


# ── CREUSET_STATE_DIR ────────────────────────────────────────────────────────

def test_state_dir_resolution(tmp_path):
    assert switch._state_dir_from({}) == ROOT / "deploy" / "state"
    assert switch._state_dir_from({"CREUSET_STATE_DIR": "  "}) == ROOT / "deploy" / "state"
    assert switch._state_dir_from({"CREUSET_STATE_DIR": str(tmp_path)}) == tmp_path
    # Relative to the repo root, not the cwd: the gate and the monitor run
    # switch.py with cwd=<repo root>, and both sides must read the same file.
    assert switch._state_dir_from({"CREUSET_STATE_DIR": "tmp/demo"}) == ROOT / "tmp" / "demo"


def test_state_dir_env_is_read_at_import(tmp_path, monkeypatch):
    monkeypatch.setenv("CREUSET_STATE_DIR", str(tmp_path))
    try:
        fresh = load_module("switch_state_dir_probe", SWITCH_PY)
    finally:
        sys.modules.pop("switch_state_dir_probe", None)
    assert fresh._STATE_DIR == tmp_path
    assert fresh._STATE_FILE == tmp_path / "state.json"
    # A throwaway state dir never falls back to the real legacy deploy/state.json.
    assert fresh._LEGACY_STATE_FILE is None


def test_cli_writes_only_into_the_configured_state_dir(tmp_path):
    default_dir = ROOT / "deploy" / "state"
    before = sorted((p.name, p.stat().st_mtime_ns) for p in default_dir.iterdir())
    env = {**os.environ, "CREUSET_STATE_DIR": str(tmp_path / "demo")}

    staged = subprocess.run([sys.executable, str(SWITCH_PY), "prepare", "green",
                             "--version", "demo-1", "--variant", "hardened"],
                            env=env, capture_output=True, text=True, timeout=60)
    assert staged.returncode == 0, staged.stdout + staged.stderr
    assert sorted(p.name for p in (tmp_path / "demo").iterdir()) == ["green.env", "state.json"]

    shown = subprocess.run([sys.executable, str(SWITCH_PY), "status"],
                           env=env, capture_output=True, text=True, timeout=60)
    assert "demo-1" in shown.stdout
    assert sorted((p.name, p.stat().st_mtime_ns) for p in default_dir.iterdir()) == before
