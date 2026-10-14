"""
Batch runner (attacks/loader.py): the case schema, portable manifests, honest
exit codes and clean interruption.

No test here starts a container, calls an LLM or reads a .env: run_case, the
image lookup and the container cleanup are replaced by recording fakes.
"""

from __future__ import annotations

import json
import shutil
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import jsonschema
import pytest
import yaml
from typer.testing import CliRunner

from conftest import ROOT, case, load_module

loader = load_module("loader", ROOT / "attacks" / "loader.py")

IMAGE = "creuset-agent:latest"
IMAGE_ID = "sha256:" + "a" * 64
OTHER_ID = "sha256:" + "b" * 64
ATTACKS = ROOT / "attacks" / "attack_library.yaml"
BENIGN = ROOT / "attacks" / "benign_tasks.yaml"


def _case(cid: str, **overrides) -> Dict[str, Any]:
    c = case(id=cid, input_payload="Summarise reports/x.txt.")
    c.pop("max_actions", None)
    c.update(overrides)
    return c


def _write_library(path: Path, cases: List[Dict[str, Any]], header: Optional[Dict[str, Any]] = None) -> Path:
    doc: Dict[str, Any] = {"cases": cases}
    if header is not None:
        doc = {"library": header, **doc}
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    return path


def _completed(cid: str, **extra) -> Dict[str, Any]:
    return {"test_id": cid, "status": "completed", "output": "done", "model": "m-1",
            "agent_image": IMAGE, "agent_image_id": IMAGE_ID, "tool_calls": [],
            "elapsed_seconds": 0.01, **extra}


class FakeRunner:
    """Stands in for sandbox run_case: records what ran, answers from a script."""

    def __init__(self, answer=None):
        self.calls: List[str] = []
        self.kwargs: List[Dict[str, Any]] = []
        self.answer = answer or (lambda cid, n: _completed(cid))
        self.lock = threading.Lock()

    def __call__(self, case_: Dict[str, Any], variant: str, **kwargs) -> Dict[str, Any]:
        with self.lock:
            self.calls.append(case_["id"])
            self.kwargs.append(kwargs)
            n = len(self.calls)
        return self.answer(case_["id"], n)


@pytest.fixture
def sandbox(monkeypatch, tmp_path):
    """The loader with every Docker-touching dependency faked out."""
    runner = FakeRunner()
    removed: List[str] = []
    monkeypatch.setattr(loader, "run_case", runner)
    monkeypatch.setattr(loader, "resolve_image", lambda image=None: (image or IMAGE, IMAGE_ID))
    monkeypatch.setattr(loader, "is_bundled_image", lambda image_id: image_id == IMAGE_ID)
    monkeypatch.setattr(loader, "validate_variant", lambda variant, image=None: None)
    monkeypatch.setattr(loader, "preflight", lambda image=None: [])
    monkeypatch.setattr(loader, "_print_warnings", lambda variant, image: None)
    monkeypatch.setattr(loader, "remove_batch_containers", lambda batch_id: removed.append(batch_id) or 0)
    monkeypatch.setattr(loader, "_git_info", lambda: {"sha": "f" * 40, "dirty": False})
    monkeypatch.setattr(loader, "RUNS_DIR", tmp_path / "runs")
    monkeypatch.setenv("AGENT_MODEL", "m-1")
    runner.removed = removed
    return runner


def _cases(n: int, prefix: str = "TT") -> List[Dict[str, Any]]:
    return [_case(f"{prefix}-{i:03d}") for i in range(1, n + 1)]


def _run_suite(tmp_path: Path, n: int, **kwargs) -> Path:
    """A batch of n trivial cases from a library of exactly those cases."""
    lib = _write_library(tmp_path / "suite.yaml", _cases(n))
    return loader.run_suite(loader.Library.read(lib).cases, "hardened", lib, **kwargs)


def _manifest(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


# ── Case schema ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("library, count, kind", [(ATTACKS, 27, "adversarial"), (BENIGN, 10, "benign")])
def test_bundled_libraries_validate_unchanged(library, count, kind):
    lib = loader.Library.read(library)
    assert len(lib.cases) == count
    assert loader.validate_library(lib) == []
    assert lib.kind == kind


def test_dry_run_still_validates_all_27_cases():
    result = CliRunner().invoke(loader.app, ["--dry-run"])
    assert result.exit_code == 0, result.output
    assert "Loaded 27 cases" in result.output and "All cases valid" in result.output


@pytest.mark.parametrize("cid", ["PI-001", "BN-010", "REFUND-0001", "ACME_PI-12345", "A1-999"])
def test_case_ids_are_a_superset_of_the_old_rule(cid):
    assert loader.validate([_case(cid)]) == []


@pytest.mark.parametrize("cid", ["pi-001", "P-001", "PI-01", "PI-123456", "PI-001\n", "../PI-001",
                                 "PI-001.json", "ABCDEFGHIJKLMNOPQ-001"])
def test_case_ids_stay_safe_as_file_names(cid):
    assert loader.validate([_case(cid)]) != []


def test_tool_names_may_be_any_lowercase_identifier():
    ok = _case("RF-001", allowed_tools=["lookup_order"], forbidden_tools=["issue_refund"],
               required_tools=["lookup_order"])
    assert loader.validate([ok]) == []
    for bad in ("Issue_Refund", "issue-refund", "1tool", ""):
        assert loader.validate([_case("RF-002", forbidden_tools=[bad])]) != [], bad


def test_new_optional_fields_are_accepted():
    c = _case("TT-001", tags=["smoke", "owasp:LLM01"], metadata={"owner": "team-a", "ticket": 12},
              max_llm_calls=4, mock_responses={"lookup_order": {"id": 7, "status": "shipped"}})
    assert loader.validate([c]) == []


@pytest.mark.parametrize("bad", [
    {"mock_response": {}},                       # misspelt: unknown fields are still errors
    {"tags": ["smoke", "smoke"]},
    {"tags": ["has space"]},
    {"metadata": "not a mapping"},
    {"max_llm_calls": 0},
    {"max_llm_calls": True},
    {"fixtures": ["no_such_fixture"]},           # the allowlist stays
])
def test_invalid_fields_are_rejected(bad):
    assert loader.validate([_case("TT-001", **bad)]) != []


def test_mock_responses_mirror_the_mock_services_bounds():
    limit = loader.MAX_MOCK_RESPONSE_BYTES
    at_limit = "x" * (limit - 2)  # a JSON string: two quotes plus its characters
    assert loader.validate([_case("TT-001", mock_responses={"t": at_limit})]) == []
    over = loader.validate([_case("TT-001", mock_responses={"t": at_limit + "x"})])
    assert over and "bytes of JSON" in over[0]
    too_many = {f"tool_{i}": i for i in range(loader.MAX_MOCK_RESPONSES + 1)}
    assert loader.validate([_case("TT-001", mock_responses=too_many)]) != []
    assert loader.validate([_case("TT-001", mock_responses={"Bad-Name": 1})]) != []


def test_mock_services_bounds_match_the_server():
    mock = load_module("mock_services_main_for_loader", ROOT / "sandbox" / "mock_services" / "main.py")
    assert loader.MAX_MOCK_RESPONSES == mock._MAX_RESPONSES
    assert loader.MAX_MOCK_RESPONSE_BYTES == mock._MAX_JSON_BYTES
    assert loader.TOOL_NAME_PATTERN == mock._TOOL_NAME


def test_exported_json_schema_equals_case_schema():
    exported = json.loads((ROOT / "schemas" / "case.v1.json").read_text(encoding="utf-8"))
    assert exported == loader.CASE_SCHEMA, (
        "schemas/case.v1.json is stale; regenerate it with `python attacks/loader.py --export-schema`")
    jsonschema.Draft202012Validator.check_schema(exported)


def test_exported_schema_accepts_every_bundled_case():
    validator = jsonschema.Draft202012Validator(
        json.loads((ROOT / "schemas" / "case.v1.json").read_text(encoding="utf-8")))
    for library in (ATTACKS, BENIGN):
        for c in loader.Library.read(library).cases:
            assert not list(validator.iter_errors(c)), c["id"]


def test_library_header_is_optional_and_checked(tmp_path):
    plain = _write_library(tmp_path / "plain.yaml", [_case("TT-001")])
    assert loader.validate_library(loader.Library.read(plain)) == []
    as_list = tmp_path / "list.yaml"
    as_list.write_text(yaml.safe_dump([_case("TT-001")]), encoding="utf-8")
    assert loader.Library.read(as_list).cases[0]["id"] == "TT-001"
    for header in ({"schema_version": 2}, {"kind": "benign"}, {"schema_version": 1, "kind": "other"},
                   {"schema_version": 1, "extra": 1}):
        lib = loader.Library.read(_write_library(tmp_path / "h.yaml", [_case("TT-001")], header))
        assert loader.validate_library(lib), header


def test_kind_comes_from_the_header_then_the_file_name(tmp_path):
    benign = loader.Library.read(_write_library(tmp_path / "refund_regressions.yaml", [_case("TT-001")],
                                                {"schema_version": 1, "kind": "benign"}))
    assert benign.kind == "benign"
    assert loader.Library.read(_write_library(tmp_path / "x_benign.yaml", [_case("TT-001")])).kind == "benign"
    assert loader.Library.read(_write_library(tmp_path / "x.yaml", [_case("TT-001")])).kind == "adversarial"


@pytest.mark.parametrize("text", ["cases: 3\n", "just a string\n", "cases: [\n"])
def test_unreadable_libraries_are_errors_not_crashes(tmp_path, text):
    path = tmp_path / "bad.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(loader.LibraryError):
        loader.Library.read(path)
    result = CliRunner().invoke(loader.app, ["--dry-run", "--library", str(path)])
    assert result.exit_code == 1


def test_every_existing_library_reader_ignores_the_header():
    # They all do raw.get("cases"): the header must not change what they see.
    import run_test
    score = load_module("_score_for_loader", ROOT / "judge" / "score.py")
    watch = load_module("_watch_for_loader", ROOT / "monitor" / "watch.py")
    ids = [c["id"] for c in loader.Library.read(ATTACKS).cases]
    assert [c["id"] for c in run_test.load_cases(ATTACKS)] == ids
    assert [c["id"] for c in score.load_library(ATTACKS)] == ids
    assert len(watch._load_forbidden_patterns()) >= 2


def test_smoke_tag_is_one_case_per_category_including_pi_002_and_pi_006():
    cases = loader.Library.read(ATTACKS).cases
    smoke = loader.select_cases(cases, tags=["smoke"])
    ids = {c["id"] for c in smoke}
    assert {"PI-002", "PI-006"} <= ids
    categories = {c["category"] for c in cases if not c.get("probe")}
    assert {c["category"] for c in smoke} == categories
    assert len(smoke) == len(categories) + 1  # PI-006 is the extra one


def test_select_cases_combines_filters():
    cases = [_case("AA-001", category="x", tags=["smoke"]), _case("AA-002", category="y", tags=["slow"]),
             _case("AA-003", category="x"), _case("JM-001", probe="judge", synthetic_transcript={})]
    assert [c["id"] for c in loader.select_cases(cases)] == ["AA-001", "AA-002", "AA-003"]
    assert [c["id"] for c in loader.select_cases(cases, tags=["smoke", "slow"])] == ["AA-001", "AA-002"]
    assert [c["id"] for c in loader.select_cases(cases, ["x"], None, ["smoke"])] == ["AA-001"]
    assert loader.select_cases(cases, ids=["JM-001"]) == []


# ── Error classes and the circuit breaker ─────────────────────────────────────

_TRACEBACK = '\nTraceback (most recent call last):\n  File "x.py", line 401, in f\n  File "y.py", line 404\n'


@pytest.mark.parametrize("error, expected", [
    ("RateLimitError: Error code: 429 - {'error': {'code': 'rate_limit_exceeded'}}", "quota"),
    ("AuthenticationError: Error code: 401 - {'error': {'code': 'invalid_api_key'}}", "auth"),
    ("NotFoundError: Error code: 404 - {'error': {'code': 'model_not_found'}}", "not_found"),
    ("PermissionDeniedError: Error code: 403 - creuset llm-proxy: egress denied", "forbidden"),
    ("APIConnectionError: Connection error.", "connection"),
    ("httpx.ConnectError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed", "connection"),
    ("InternalServerError: Error code: 502 - <html>502 Bad Gateway</html>", "connection"),
    ("ValueError: the agent tripped over itself", None),
    ("ValueError: unrelated" + _TRACEBACK, None),  # line numbers are not status codes
])
def test_errors_are_classified_from_the_error_text(error, expected):
    assert loader.classify_error({"status": "error", "error": error}) == expected


def test_a_completed_case_has_no_error_class():
    assert loader.classify_error({"status": "completed", "error": "Error code: 401"}) is None


def test_quota_breaker_behaviour_is_unchanged(monkeypatch):
    monkeypatch.setattr(loader, "_QUOTA_BREAKER", 3)
    quota = {"status": "error", "error": "429 rate limit"}
    ok = {"status": "completed"}
    breaker = loader._Breaker()
    assert [breaker.record(t) for t in (quota, quota, ok, quota, quota)] == [None] * 5
    assert breaker.record(quota) == "quota"


def test_breaker_trips_on_consecutive_failures_of_one_class(monkeypatch):
    monkeypatch.setattr(loader, "_ERROR_BREAKER", 3)
    auth = {"status": "error", "error": "AuthenticationError: Error code: 401"}
    conn = {"status": "error", "error": "APIConnectionError: Connection error."}
    breaker = loader._Breaker()
    assert [breaker.record(t) for t in (auth, auth, conn, auth, auth)] == [None] * 5
    assert breaker.record(auth) == "auth"


def test_a_wrong_key_stops_the_batch_after_three_cases(sandbox, tmp_path):
    def answer(cid, n):
        if n > 3:
            time.sleep(0.2)  # a real case takes far longer than the breaker needs to react
        return {"test_id": cid, "status": "error",
                "error": "AuthenticationError: Error code: 401 - invalid_api_key"}

    sandbox.answer = answer
    path = _run_suite(tmp_path, 10, workers=1)
    manifest = _manifest(path)
    # Three to trip it, plus at most the one already in flight on the one worker.
    assert 3 <= len(sandbox.calls) <= 4
    assert len(manifest["cases"]) == len(sandbox.calls)
    assert manifest["complete"] is False
    assert manifest["stopped"]["reason"] == "circuit_breaker"
    assert manifest["stopped"]["error_class"] == "auth"
    assert loader.batch_exit_code(manifest) == 3


# ── Manifest v1 ───────────────────────────────────────────────────────────────

def test_manifest_v1_is_portable_and_records_provenance(sandbox):
    lib = loader.Library.read(ATTACKS)
    selected = loader.select_cases(lib.cases, tags=["smoke"])
    path = loader.run_suite(selected, "hardened", ATTACKS, selected_ids=[c["id"] for c in selected],
                            tags=["smoke"], source=lib)
    m = _manifest(path)
    batch = path.parent
    assert m["schema_version"] == 1
    assert m["library"] == "attacks/attack_library.yaml"
    assert m["library_snapshot"] == "library.yaml"
    assert (batch / "library.yaml").read_bytes() == ATTACKS.read_bytes()
    assert m["library_sha256"] == lib.sha256
    assert m["kind"] == "adversarial"
    assert m["tags"] == ["smoke"] and m["selected_ids"] == [c["id"] for c in selected]
    assert m["agent_model"] == "m-1"
    assert (m["agent_image"], m["agent_image_id"]) == (IMAGE, IMAGE_ID)
    assert m["git"] == {"sha": "f" * 40, "dirty": False}
    assert m["complete"] is True and m["stopped"] is None and m["case_count"] == len(selected)
    for entry in m["cases"]:
        assert entry["transcript"] == f"{entry['id']}.json"
        assert (batch / entry["transcript"]).is_file()
        assert entry["agent_image_id"] == IMAGE_ID and entry["agent_model"] == "m-1"
    assert "D:\\" not in path.read_text(encoding="utf-8") and str(ROOT) not in path.read_text(encoding="utf-8")
    assert all(kw["image"] == IMAGE and kw["batch_id"] == m["batch_id"] for kw in sandbox.kwargs)
    assert loader.batch_exit_code(m) == 0


def test_a_library_outside_the_repo_is_recorded_absolute(sandbox, tmp_path):
    lib = _write_library(tmp_path / "team_suite.yaml", [_case("TT-001")])
    m = _manifest(loader.run_suite(loader.Library.read(lib).cases, "hardened", lib))
    assert m["library"] == str(lib.resolve())


def test_the_manifest_exists_before_the_first_case_finishes(sandbox, tmp_path):
    seen = {}

    def answer(cid, n):
        manifests = list(loader.RUNS_DIR.glob("*/manifest.json"))
        seen["manifest"] = _manifest(manifests[0]) if manifests else None
        return _completed(cid)

    sandbox.answer = answer
    _run_suite(tmp_path, 1)
    assert seen["manifest"] is not None
    assert seen["manifest"]["complete"] is False and seen["manifest"]["cases"] == []


def test_two_batches_in_the_same_second_get_separate_folders(sandbox, tmp_path, monkeypatch):
    monkeypatch.setattr(loader.time, "strftime", lambda fmt, *a: "20261014-120000")
    first = _run_suite(tmp_path, 1)
    second = _run_suite(tmp_path, 1)
    assert first.parent != second.parent
    assert second.parent.name.endswith("-2")


def test_malformed_tool_calls_do_not_crash_the_batch(sandbox, tmp_path):
    sandbox.answer = lambda cid, n: _completed(cid, tool_calls=[None, {"input": {}}, {"tool": "read_file"}])
    assert _manifest(_run_suite(tmp_path, 1))["complete"]
    sandbox.answer = lambda cid, n: _completed(cid, tool_calls=None)
    assert _manifest(_run_suite(tmp_path, 1))["complete"]


def test_a_crashing_case_is_recorded_not_lost(sandbox, tmp_path):
    def answer(cid, n):
        raise RuntimeError("docker exploded")

    sandbox.answer = answer
    m = _manifest(_run_suite(tmp_path, 1))
    assert m["cases"][0]["status"] == "harness_error"
    assert loader.batch_exit_code(m) == 3


@pytest.mark.parametrize("manifest, code", [
    ({"complete": True, "case_count": 1, "cases": [{"id": "A", "status": "completed"}]}, 0),
    ({"complete": True, "case_count": 1, "cases": [{"id": "A", "status": "error"}]}, 3),
    ({"complete": False, "case_count": 2, "cases": [{"id": "A", "status": "completed"}]}, 3),
    ({"complete": True, "case_count": 0, "cases": []}, 3),
    ({"complete": True, "case_count": 1, "cases": [{"id": "A", "status": "completed"}],
      "stopped": {"reason": "interrupted"}}, 3),
])
def test_batch_exit_codes(manifest, code):
    assert loader.batch_exit_code(manifest) == code


# ── Resume ────────────────────────────────────────────────────────────────────

def test_a_moved_batch_resumes_offline_with_nothing_to_do(sandbox, tmp_path, monkeypatch):
    path = _run_suite(tmp_path, 3)
    moved = tmp_path / "elsewhere" / "batch"
    shutil.move(str(path.parent), str(moved))

    def no_docker(image=None):
        raise AssertionError("a finished batch must resume without Docker")

    monkeypatch.setattr(loader, "resolve_image", no_docker)
    monkeypatch.setattr(loader, "preflight", no_docker)
    assert loader.resume_suite(moved) == moved / "manifest.json"
    assert sandbox.calls == ["TT-001", "TT-002", "TT-003"]  # nothing ran again


def _legacy_batch(tmp_path: Path, statuses: Dict[str, str]) -> Path:
    """A batch as the pre-v1 loader wrote it on Windows: absolute paths everywhere."""
    batch = tmp_path / "20260920-043334_hardened_attack_library"
    batch.mkdir()
    entries = []
    for cid, status in statuses.items():
        (batch / f"{cid}.json").write_text(json.dumps(_completed(cid, status=status, model="m-1")),
                                           encoding="utf-8")
        entries.append({"id": cid, "status": status,
                        "transcript": f"D:\\projects\\Creuset\\logs\\runs\\{batch.name}\\{cid}.json",
                        "agent_model": "m-1", "elapsed_seconds": 1.0})
    (batch / "manifest.json").write_text(json.dumps({
        "ts": 1, "variant": "hardened", "library": "D:\\projects\\Creuset\\attacks\\attack_library.yaml",
        "categories": None, "selected_ids": list(statuses), "agent_model": "m-1",
        "case_count": len(statuses), "complete": True, "cases": entries,
    }), encoding="utf-8")
    return batch


def test_a_legacy_windows_manifest_still_resumes(sandbox, tmp_path):
    batch = _legacy_batch(tmp_path, {"PI-001": "completed", "PI-002": "error"})
    loader.resume_suite(batch)
    assert sandbox.calls == ["PI-002"]
    m = _manifest(batch / "manifest.json")
    assert [e["transcript"] for e in m["cases"]] == ["PI-001.json", "PI-002.json"]
    assert m["complete"] is True and loader.batch_exit_code(m) == 0
    assert m["resumes"][-1]["reran"] == ["PI-002"]


def test_resume_refuses_a_different_agent_image(sandbox, tmp_path, monkeypatch):
    path = _run_suite(tmp_path, 2)
    (path.parent / "TT-002.json").unlink()
    monkeypatch.setattr(loader, "resolve_image", lambda image=None: (IMAGE, OTHER_ID))
    with pytest.raises(ValueError, match="two agent builds"):
        loader.resume_suite(path.parent)
    loader.resume_suite(path.parent, allow_image_change=True)
    m = _manifest(path)
    assert sandbox.calls[-1] == "TT-002"
    assert m["agent_image_id"] == OTHER_ID and m["resumes"][-1]["agent_image_id"] == OTHER_ID


def test_resume_still_refuses_a_different_model(sandbox, tmp_path, monkeypatch):
    path = _run_suite(tmp_path, 2)
    (path.parent / "TT-002.json").unlink()
    monkeypatch.setenv("AGENT_MODEL", "m-2")
    with pytest.raises(ValueError, match="two models"):
        loader.resume_suite(path.parent)


def test_resume_runs_the_snapshot_and_refuses_a_tampered_one(sandbox, tmp_path):
    lib_path = _write_library(tmp_path / "suite.yaml", [_case("TT-001"), _case("TT-002")])
    path = loader.run_suite(loader.Library.read(lib_path).cases, "hardened", lib_path)
    (path.parent / "TT-002.json").unlink()
    # Editing the library after the run changes nothing for the batch...
    _write_library(lib_path, [_case("TT-001"), _case("TT-002", input_payload="something else")])
    loader.resume_suite(path.parent)
    assert sandbox.calls[-1] == "TT-002"
    assert sandbox.kwargs[-1]["image"] == IMAGE
    # ...but a snapshot that no longer matches its recorded hash is refused.
    (path.parent / "library.yaml").write_text("cases: []\n", encoding="utf-8")
    with pytest.raises(ValueError, match="does not match"):
        loader.resume_suite(path.parent)


def test_resume_reruns_a_completed_case_whose_transcript_is_gone(sandbox, tmp_path):
    path = _run_suite(tmp_path, 2)
    (path.parent / "TT-001.json").unlink()
    loader.resume_suite(path.parent)
    assert sandbox.calls == ["TT-001", "TT-002", "TT-001"]


def test_resume_keeps_a_tag_selected_scope(sandbox, tmp_path):
    lib_path = _write_library(tmp_path / "suite.yaml",
                              [_case("TT-001", tags=["smoke"]), _case("TT-002"), _case("TT-003", tags=["smoke"])])
    lib = loader.Library.read(lib_path)
    selected = loader.select_cases(lib.cases, tags=["smoke"])
    path = loader.run_suite(selected, "hardened", lib_path, selected_ids=[c["id"] for c in selected],
                            tags=["smoke"], source=lib)
    (path.parent / "TT-003.json").unlink()
    loader.resume_suite(path.parent)
    assert sandbox.calls == ["TT-001", "TT-003", "TT-003"]
    assert [e["id"] for e in _manifest(path)["cases"]] == ["TT-001", "TT-003"]


# ── Interruption ──────────────────────────────────────────────────────────────

def _interrupt_on_second_case(signum):
    def answer(cid, n):
        if n == 2:
            signal.raise_signal(signum)  # handled in the main thread, as Ctrl-C is
            # Still in flight for longer than the main thread's poll, as a real
            # case (30-180 s) always is.
            time.sleep(loader._POLL_SECONDS + 0.4)
        return _completed(cid)
    return answer


@pytest.mark.parametrize("signame", ["SIGINT", "SIGTERM"])
def test_an_interrupt_runs_at_most_the_in_flight_cases_and_keeps_the_finished_ones(sandbox, tmp_path, signame):
    if signame == "SIGTERM" and sys.platform == "win32":
        pytest.skip("SIGTERM cannot be raised meaningfully on Windows")
    signum = getattr(signal, signame)
    previous = signal.getsignal(signum)
    sandbox.answer = _interrupt_on_second_case(signum)

    with pytest.raises(loader.BatchInterrupted) as stopped:
        _run_suite(tmp_path, 10, workers=1)

    batch = stopped.value.manifest_path.parent
    m = _manifest(stopped.value.manifest_path)
    assert sandbox.calls == ["TT-001", "TT-002"]          # the 8 queued cases never started
    assert sorted(p.name for p in batch.glob("TT-*.json")) == ["TT-001.json", "TT-002.json"]
    assert [e["id"] for e in m["cases"]] == ["TT-001", "TT-002"]
    assert m["complete"] is False
    assert m["stopped"]["reason"] == "interrupted" and m["stopped"]["signal"] == signame
    assert sandbox.removed == [m["batch_id"]]             # its containers were reaped by label
    assert loader.batch_exit_code(m) == 3
    assert signal.getsignal(signum) == previous           # the caller's handler is back

    # --resume runs only what never ran.
    loader.resume_suite(batch)
    assert sandbox.calls[2:] == [f"TT-{i:03d}" for i in range(3, 11)]
    assert _manifest(batch / "manifest.json")["complete"] is True


def test_the_cli_exits_3_after_an_interrupt_and_still_names_the_manifest(sandbox, tmp_path):
    sandbox.answer = _interrupt_on_second_case(signal.SIGINT)
    lib = _write_library(tmp_path / "suite.yaml", _cases(5))
    out = tmp_path / "manifest.txt"
    result = CliRunner().invoke(loader.app, ["--library", str(lib), "--variant", "hardened",
                                             "--manifest-out", str(out)])
    assert result.exit_code == 3, result.output
    manifest_path = Path(out.read_text(encoding="utf-8").strip())
    assert result.output.strip().splitlines()[-1] == str(manifest_path)
    assert _manifest(manifest_path)["stopped"]["reason"] == "interrupted"


# ── CLI ───────────────────────────────────────────────────────────────────────

def _invoke(*args: str):
    return CliRunner().invoke(loader.app, list(args))


def test_unknown_case_ids_exit_2_without_running_anything(sandbox):
    result = _invoke("--cases", "ZZ-999")
    assert result.exit_code == 2, result.output
    assert "ZZ-999" in result.output and sandbox.calls == []


@pytest.mark.parametrize("args", [["--tag", "no-such-tag"], ["--cases", "JM-001"],
                                  ["--cases", "PI-001", "--category", "jailbreak"]])
def test_selecting_nothing_exits_2(sandbox, args):
    assert _invoke(*args).exit_code == 2
    assert sandbox.calls == []


def test_a_missing_image_exits_2(sandbox, monkeypatch):
    def missing(image=None):
        raise RuntimeError("Agent image 'nope:1' not found")

    monkeypatch.setattr(loader, "resolve_image", missing)
    result = _invoke("--cases", "PI-001", "--image", "nope:1")
    assert result.exit_code == 2 and "not found" in result.output


def test_a_bad_variant_and_a_failed_preflight_exit_2(sandbox, monkeypatch):
    monkeypatch.setattr(loader, "validate_variant", lambda v, image=None: "unknown variant 'x'")
    assert _invoke("--cases", "PI-001", "--variant", "x").exit_code == 2
    monkeypatch.setattr(loader, "preflight", lambda image=None: ["Docker not available"])
    assert _invoke("--cases", "PI-001").exit_code == 2
    assert sandbox.calls == []


def test_an_invalid_library_exits_1_on_dry_run_and_2_otherwise(sandbox, tmp_path):
    lib = _write_library(tmp_path / "bad.yaml", [_case("TT-001", severity="catastrophic")])
    assert _invoke("--dry-run", "--library", str(lib)).exit_code == 1
    assert _invoke("--library", str(lib)).exit_code == 2


def test_complete_batch_exits_0_and_a_failed_case_exits_3(sandbox, tmp_path):
    lib = _write_library(tmp_path / "suite.yaml", _cases(2))
    out = tmp_path / "out" / "manifest.txt"
    batches = tmp_path / "batches"
    result = _invoke("--library", str(lib), "--batch-dir", str(batches), "--manifest-out", str(out))
    assert result.exit_code == 0, result.output
    manifest_path = Path(out.read_text(encoding="utf-8").strip())
    assert manifest_path.parent.parent == batches.resolve()
    assert result.output.strip().splitlines()[-1] == str(manifest_path)

    sandbox.answer = lambda cid, n: {"test_id": cid, "status": "error", "error": "boom"}
    result = _invoke("--library", str(lib), "--batch-dir", str(batches), "--manifest-out", str(out))
    assert result.exit_code == 3, result.output


def test_a_stale_manifest_out_is_removed_when_nothing_runs(sandbox, tmp_path):
    out = tmp_path / "manifest.txt"
    out.write_text("logs/runs/an-old-batch/manifest.json\n", encoding="utf-8")
    assert _invoke("--cases", "ZZ-999", "--manifest-out", str(out)).exit_code == 2
    assert not out.exists()


def test_tag_selects_cases_and_is_recorded(sandbox, tmp_path):
    out = tmp_path / "m.txt"
    result = _invoke("--tag", "smoke", "--manifest-out", str(out))
    assert result.exit_code == 0, result.output
    m = _manifest(Path(out.read_text(encoding="utf-8").strip()))
    assert m["tags"] == ["smoke"]
    assert set(m["selected_ids"]) == set(sandbox.calls) >= {"PI-002", "PI-006"}


def test_the_bundled_image_refuses_tools_it_does_not_have(sandbox, tmp_path, monkeypatch):
    lib = _write_library(tmp_path / "suite.yaml", [_case("TT-001", forbidden_tools=["send_mail"])])
    result = _invoke("--library", str(lib))
    assert result.exit_code == 2 and "send_mail" in result.output
    monkeypatch.setattr(loader, "is_bundled_image", lambda image_id: False)
    assert _invoke("--library", str(lib), "--image", "my-agent:1").exit_code == 0
    assert sandbox.kwargs[-1]["image"] == "my-agent:1"


def test_workers_default_to_one(monkeypatch):
    # GATE_WORKERS=2 exceeded the free tier's tokens-per-minute cap before a
    # single token was generated; run_suite, resume_suite and .env.example all say 1.
    import dotenv
    import typer

    monkeypatch.delenv("GATE_WORKERS", raising=False)
    monkeypatch.setattr(dotenv, "load_dotenv", lambda *a, **k: False)  # ignore a developer's .env
    fresh = load_module("_loader_defaults", ROOT / "attacks" / "loader.py")
    params = {p.name: p for p in typer.main.get_command(fresh.app).params}
    assert params["workers"].default == 1


def test_resume_exit_codes(sandbox, tmp_path):
    batch = _legacy_batch(tmp_path, {"PI-001": "completed"})
    assert _invoke("--resume", str(batch)).exit_code == 0
    assert _invoke("--resume", str(tmp_path / "nowhere")).exit_code == 2
    sandbox.answer = lambda cid, n: {"test_id": cid, "status": "error", "error": "boom"}
    assert _invoke("--resume", str(batch), "--redo", "PI-001").exit_code == 3
