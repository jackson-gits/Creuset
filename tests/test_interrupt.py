"""
Stopping a batch: Ctrl-C / SIGTERM keep every finished run, start nothing new,
remove the batch's containers, and leave a manifest --resume can finish. A
batch killed outright still has one, never more than a run behind.

The signals are real (signal.raise_signal from the fake agent), so the handler
loader.py installs is what is under test.
"""

import json
import signal
import threading

import pytest
import yaml

import loader
import run_test

CLEAN = {"status": "completed", "output": "ok", "tool_calls": [], "steps": [], "service_audit": []}


def _case(cid):
    return {"id": cid, "category": "prompt_injection", "severity": "high", "scenario": "s",
            "input_payload": "hi", "expected_behavior": "e", "allowed_tools": [],
            "forbidden_tools": [], "forbidden_output_patterns": []}


CASES = [_case(f"EX-00{n}") for n in range(1, 5)]


class Removed(list):
    """Stands in for remove_containers: records the batch, and says when the stop has happened."""

    def __init__(self):
        super().__init__()
        self.happened = threading.Event()

    def __call__(self, batch_id=None):
        self.append(batch_id)
        self.happened.set()
        return 3


@pytest.fixture
def batch(tmp_path, monkeypatch):
    monkeypatch.setattr(loader, "RUNS_DIR", tmp_path / "runs")
    monkeypatch.setattr(loader, "image_id", lambda image: None)
    removed = Removed()
    monkeypatch.setattr(loader, "remove_containers", removed)
    lib = tmp_path / "lib.yaml"
    lib.write_text(yaml.safe_dump({"cases": CASES}), encoding="utf-8")
    return lib, removed


def _signal_and_wait(sig, removed):
    # The handler runs on the main thread, at its next poll; a real run is still
    # going then. Returning only once the stop has happened makes that so here.
    signal.raise_signal(getattr(signal, sig))
    assert removed.happened.wait(10)


def _manifest(path):
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("sig", ["SIGINT", "SIGTERM"])
def test_a_signal_keeps_finished_runs_and_starts_nothing_new(batch, monkeypatch, sig):
    lib, removed = batch
    started = []

    def agent(case, variant, subject=None, batch_id=None):
        started.append((case["id"], batch_id))
        if case["id"] == "EX-002":
            _signal_and_wait(sig, removed)
        return dict(CLEAN)
    monkeypatch.setattr(loader, "run_case", agent)

    with pytest.raises(loader.BatchInterrupted) as stop:
        loader.run_suite(CASES, "hardened", lib, workers=1)
    manifest = _manifest(stop.value.manifest_path)
    # EX-002 completed although the stop came first: a finished run is a
    # result, and kept. EX-003 and EX-004 never started.
    assert [e["id"] for e in manifest["cases"]] == ["EX-001", "EX-002"]
    assert [cid for cid, _ in started] == ["EX-001", "EX-002"]
    assert manifest["complete"] is False
    assert manifest["stopped"] == {"reason": "interrupted", "signal": sig, "containers_removed": 3}
    # Every container of THIS batch, by its own label, and nothing wider.
    (batch_id,) = {b for _, b in started}
    assert removed == [batch_id] and batch_id


def test_a_run_the_stop_cut_off_is_not_a_result(batch, monkeypatch):
    lib, _ = batch
    cut_off = threading.Event()

    def agent(case, variant, subject=None, batch_id=None):
        if case["id"] == "EX-001":
            # Still running when EX-002 signals; its container is then removed
            # under it, and `docker run` returns an error.
            cut_off.wait(10)
            return {"status": "container_error", "error": "container removed"}
        signal.raise_signal(signal.SIGINT)
        return dict(CLEAN)
    monkeypatch.setattr(loader, "run_case", agent)
    monkeypatch.setattr(loader, "remove_containers", lambda batch_id=None: cut_off.set() or 1)

    with pytest.raises(loader.BatchInterrupted) as stop:
        loader.run_suite(CASES[:2], "hardened", lib, workers=2)
    batch_dir = stop.value.manifest_path.parent
    assert [e["id"] for e in _manifest(stop.value.manifest_path)["cases"]] == ["EX-002"]
    # No fail-closed FAIL for an attack that was never finished.
    assert not (batch_dir / "EX-001.json").exists()


def test_the_manifest_is_on_disk_before_the_first_run_and_after_each(batch, monkeypatch):
    lib, _ = batch
    seen, writes = [], []

    def agent(case, variant, subject=None, batch_id=None):
        (manifest_path,) = list((loader.RUNS_DIR).glob("*/manifest.json"))   # exists from the start
        seen.append(_manifest(manifest_path)["complete"])
        return dict(CLEAN)
    monkeypatch.setattr(loader, "run_case", agent)
    real_write = loader.write_json
    monkeypatch.setattr(loader, "write_json", lambda path, data: (
        writes.append(len(data["cases"])) if path.name == "manifest.json" else None) or real_write(path, data))
    manifest = _manifest(loader.run_suite(CASES[:3], "hardened", lib, workers=1))
    assert seen == [False, False, False]
    # Up front, after each of the three runs, and the final one.
    assert writes == [0, 1, 2, 3, 3]
    assert manifest["complete"] is True and "stopped" not in manifest


def test_an_interrupted_batch_resumes_where_it_stopped(batch, monkeypatch):
    lib, _ = batch
    calls = []

    def stopping_agent(case, variant, subject=None, batch_id=None):
        calls.append(case["id"])
        if case["id"] == "EX-002":
            _signal_and_wait("SIGINT", batch[1])
        return dict(CLEAN)
    monkeypatch.setattr(loader, "run_case", stopping_agent)
    with pytest.raises(loader.BatchInterrupted) as stop:
        loader.run_suite(CASES, "hardened", lib, workers=1)

    monkeypatch.setattr(loader, "preflight", lambda *a: [])
    calls.clear()
    monkeypatch.setattr(loader, "run_case", lambda case, *a, **k: calls.append(case["id"]) or dict(CLEAN))
    manifest = _manifest(loader.resume_suite(stop.value.manifest_path.parent))
    assert calls == ["EX-003", "EX-004"]
    assert manifest["complete"] is True and "stopped" not in manifest
    assert manifest["resumes"][-1]["reran"] == ["EX-003", "EX-004"]


def test_the_handlers_are_put_back_afterwards(batch, monkeypatch):
    lib, _ = batch
    before = signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM)
    monkeypatch.setattr(loader, "run_case", lambda *a, **k: dict(CLEAN))
    loader.run_suite(CASES[:1], "hardened", lib, workers=1)
    assert (signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM)) == before


def test_the_cli_exits_130_and_names_the_resume_command(batch, monkeypatch, tmp_path):
    from typer.testing import CliRunner
    lib, _ = batch
    manifest_path = tmp_path / "b" / "manifest.json"
    manifest_path.parent.mkdir()
    manifest_path.write_text(json.dumps({"cases": [{"id": "EX-001"}], "stopped": {
        "reason": "interrupted", "containers_removed": 2}}), encoding="utf-8")
    monkeypatch.setattr(loader, "preflight", lambda *a: [])

    def interrupted(*a, **k):
        raise loader.BatchInterrupted(manifest_path)
    monkeypatch.setattr(loader, "run_suite", interrupted)
    result = CliRunner().invoke(loader.app, ["--library", str(lib), "--variant", "hardened"])
    assert result.exit_code == 130
    assert "--resume" in result.output and "1 finished run(s) kept" in result.output


# ── The harness side: labels and cleanup ──────────────────────────────────────

class Ps:
    def __init__(self, ids):
        self.ids, self.calls = ids, []

    def __call__(self, args, timeout=60, input=None):
        self.calls.append(args)
        if args[:2] == ["ps", "-aq"]:
            return run_test.subprocess.CompletedProcess(args, 0, "\n".join(self.ids), "")
        if args[:2] == ["rm", "-f"]:
            return run_test.subprocess.CompletedProcess(args, 0, "\n".join(args[2:]), "")
        if args[:2] == ["volume", "ls"]:
            return run_test.subprocess.CompletedProcess(args, 0, "creuset-in-x\n" if self.ids else "", "")
        if args[:2] == ["volume", "rm"]:
            return run_test.subprocess.CompletedProcess(args, 0, "", "")
        raise AssertionError(args)


def test_cleanup_removes_one_batch_by_its_label(monkeypatch):
    fake = Ps(["c1", "c2"])
    monkeypatch.setattr(run_test, "_docker", fake)
    assert run_test.remove_containers("20261015-abc") == 2
    ps = fake.calls[0]
    assert f"label={run_test.STACK_LABEL}" in ps and "label=creuset.batch=20261015-abc" in ps
    assert fake.calls[1] == ["rm", "-f", "c1", "c2"]
    # The volume transport's input volumes go too, by the same labels.
    assert fake.calls[2] == ["volume", "ls", "-q", *ps[2:]]
    assert fake.calls[3] == ["volume", "rm", "-f", "creuset-in-x"]


@pytest.mark.parametrize("bad", ["", "a b", "-x", "x\ny"])
def test_cleanup_never_widens_on_an_odd_batch_id(monkeypatch, bad):
    fake = Ps(["c1"])
    monkeypatch.setattr(run_test, "_docker", fake)
    assert run_test.remove_containers(bad) == 0 and fake.calls == []


def test_without_a_batch_cleanup_is_this_stack_only(monkeypatch):
    fake = Ps([])
    monkeypatch.setattr(run_test, "_docker", fake)
    assert run_test.remove_containers() == 0
    assert fake.calls == [["ps", "-aq", "--filter", f"label={run_test.STACK_LABEL}"],
                          ["volume", "ls", "-q", "--filter", f"label={run_test.STACK_LABEL}"]]
