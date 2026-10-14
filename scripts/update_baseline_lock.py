"""
scripts/update_baseline_lock.py
────────────────────────────────
Fingerprint every surface that decides what the published measurements MEAN.

Creuset's results (naive FAIL / hardened PASS / broken FAIL, and the judge
scores beside them) are only comparable across commits if none of these change:

  • the agent under test: its prompts and its loop (agent/variants/*.txt,
    agent/run_agent.py, agent/tools.py, agent/callbacks.py);
  • what each case asks and how it is graded (every grading field of every case
    in attacks/*.yaml — tags and other metadata deliberately excluded);
  • the world the agent acts in (mock-services' base files, fake DB, fixtures);
  • the judge's prompt text (system prompt and user template);
  • the default severity thresholds.

tests/test_baseline_lock.py recomputes these hashes and fails, naming the keys,
when one moves. That is not a ban: a deliberate measurement-affecting change is
fine, but it must be a decision — re-run this script, and record it under
"Measurement-affecting" in CHANGELOG.md, so published numbers are never quietly
compared across a boundary they cannot cross.

Usage:
    python scripts/update_baseline_lock.py          # rewrite baseline.lock.json
    python scripts/update_baseline_lock.py --check  # exit 1 and list drift
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict

import yaml

ROOT = Path(__file__).resolve().parent.parent
LOCK_FILE = ROOT / "baseline.lock.json"

# The fields of a case that determine what it tests and how it is graded.
# Anything else (tags, metadata) can change freely without touching results.
CASE_FIELDS = (
    "category", "severity", "scenario", "input_payload", "expected_behavior",
    "allowed_tools", "forbidden_tools", "required_tools", "forbidden_output_patterns",
    "max_actions", "max_llm_calls", "fixtures", "probe", "synthetic_transcript",
)
AGENT_FILES = ("agent/run_agent.py", "agent/tools.py", "agent/callbacks.py")
LIBRARIES = ("attacks/attack_library.yaml", "attacks/benign_tasks.yaml")


def _sha(data: Any) -> str:
    if isinstance(data, bytes):
        raw = data
    elif isinstance(data, str):
        raw = data.encode("utf-8")
    else:
        raw = json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _text_file(rel: str) -> str:
    # Line endings normalised: a Windows checkout (CRLF) is the same measurement.
    return (ROOT / rel).read_bytes().decode("utf-8").replace("\r\n", "\n")


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def compute() -> Dict[str, str]:
    """Return {surface key: sha256} for every measurement-affecting surface."""
    out: Dict[str, str] = {}

    for path in sorted((ROOT / "agent" / "variants").glob("*.txt")):
        out[f"agent/variants/{path.name}"] = _sha(_text_file(f"agent/variants/{path.name}"))
    for rel in AGENT_FILES:
        out[rel] = _sha(_text_file(rel))

    for rel in LIBRARIES:
        raw = yaml.safe_load(_text_file(rel))
        cases = raw if isinstance(raw, list) else raw.get("cases", [])
        for case in cases:
            graded = {k: case[k] for k in CASE_FIELDS if k in case}
            out[f"{rel}#{case['id']}"] = _sha(graded)

    judge = _load("_baseline_model_judge", "judge/model_judge.py")
    out["judge/model_judge.py#_SYSTEM_PROMPT"] = _sha(judge._SYSTEM_PROMPT)
    out["judge/model_judge.py#_USER_TEMPLATE"] = _sha(judge._USER_TEMPLATE)

    mock = _load("_baseline_mock_services", "sandbox/mock_services/main.py")
    out["sandbox/mock_services/main.py#_BASE_FILES"] = _sha(mock._BASE_FILES)
    out["sandbox/mock_services/main.py#_BASE_DB"] = _sha(mock._BASE_DB)
    out["sandbox/mock_services/main.py#_FIXTURES"] = _sha(mock._FIXTURES)

    # Defaults only: what a run with no THRESHOLD_* overrides would apply.
    saved = {k: os.environ.pop(k) for k in list(os.environ) if k.startswith("THRESHOLD_")}
    try:
        sys.path.insert(0, str(ROOT / "judge"))
        score = _load("_baseline_score", "judge/score.py")
        out["judge/score.py#THRESHOLDS"] = _sha(score.THRESHOLDS)
    finally:
        os.environ.update(saved)
    return out


def diff(expected: Dict[str, str], actual: Dict[str, str]) -> Dict[str, str]:
    """{key: 'changed' | 'added' | 'removed'} for every surface that moved."""
    keys = set(expected) | set(actual)
    return {k: ("added" if k not in expected else "removed" if k not in actual else "changed")
            for k in sorted(keys) if expected.get(k) != actual.get(k)}


def main(argv: list) -> int:
    actual = compute()
    if "--check" in argv:
        expected = json.loads(LOCK_FILE.read_text(encoding="utf-8"))["surfaces"]
        drift = diff(expected, actual)
        for key, kind in drift.items():
            print(f"{kind:8} {key}")
        return 1 if drift else 0
    LOCK_FILE.write_text(json.dumps({
        "_comment": ("Fingerprints of every measurement-affecting surface. Regenerate with "
                     "scripts/update_baseline_lock.py ONLY for a deliberate change, and record it "
                     "under 'Measurement-affecting' in CHANGELOG.md."),
        "surfaces": actual,
    }, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(f"Wrote {len(actual)} fingerprints to {LOCK_FILE.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
