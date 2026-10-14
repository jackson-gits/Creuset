"""
Measurement comparability: nothing that changes what the published results mean
may change by accident. See scripts/update_baseline_lock.py.
"""

import json

from conftest import ROOT, load_module

lock = load_module("update_baseline_lock", ROOT / "scripts" / "update_baseline_lock.py")


def test_measurement_surfaces_unchanged():
    expected = json.loads(lock.LOCK_FILE.read_text(encoding="utf-8"))["surfaces"]
    drift = lock.diff(expected, lock.compute())
    assert not drift, (
        "measurement-affecting change: "
        + ", ".join(f"{k} ({v})" for k, v in drift.items())
        + ". If deliberate, run scripts/update_baseline_lock.py and add a CHANGELOG "
          "'Measurement-affecting' entry; otherwise revert it."
    )


def test_lock_covers_every_case_and_variant():
    surfaces = json.loads(lock.LOCK_FILE.read_text(encoding="utf-8"))["surfaces"]
    assert sum(k.startswith("attacks/attack_library.yaml#") for k in surfaces) == 27
    assert sum(k.startswith("attacks/benign_tasks.yaml#") for k in surfaces) == 10
    assert {"agent/variants/naive.txt", "agent/variants/hardened.txt",
            "agent/variants/broken.txt"} <= set(surfaces)


def test_metadata_does_not_count_as_a_measurement_change():
    case = {"id": "X-001", "category": "c", "severity": "high", "input_payload": "p"}
    graded = {k: case[k] for k in lock.CASE_FIELDS if k in case}
    tagged = dict(case, tags=["smoke"], metadata={"owner": "x"})
    assert graded == {k: tagged[k] for k in lock.CASE_FIELDS if k in tagged}


def test_line_endings_do_not_count(tmp_path, monkeypatch):
    (tmp_path / "f.txt").write_bytes(b"a\r\nb\r\n")
    monkeypatch.setattr(lock, "ROOT", tmp_path)
    assert lock._sha(lock._text_file("f.txt")) == lock._sha("a\nb\n")
