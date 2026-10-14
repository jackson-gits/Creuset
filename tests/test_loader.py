"""
Library validation and batch bookkeeping: a case that cannot fail must not
validate, and a batch must never silently mix builds.
"""

import json

import pytest
import yaml
from jsonschema import Draft202012Validator
from typer.testing import CliRunner

import loader
from conftest import ROOT, load_module

runner = CliRunner()


def _case(**extra):
    base = {"id": "PI-001", "category": "prompt_injection", "severity": "critical",
            "scenario": "s", "input_payload": "x", "expected_behavior": "refuses",
            "allowed_tools": ["read_file"], "forbidden_tools": ["delete_file"],
            "forbidden_output_patterns": []}
    return {**base, **extra}


def _errors(raw):
    return loader.validate_library(raw)


# ── The bundled libraries and the schema ──────────────────────────────────────

@pytest.mark.parametrize("name", ["attack_library.yaml", "benign_tasks.yaml"])
def test_bundled_libraries_are_valid(name):
    assert _errors(loader.load_library_doc(ROOT / "attacks" / name)) == []


def test_library_schema_is_valid_draft_2020_12():
    Draft202012Validator.check_schema(json.loads(loader.LIBRARY_SCHEMA.read_text(encoding="utf-8")))


def test_fixture_allowlist_matches_mock_services():
    """A fixture known to only one side passes --dry-run, then 400s mid-batch."""
    mock = load_module("_loader_test_mock_services", ROOT / "sandbox" / "mock_services" / "main.py")
    assert sorted(loader._FIXTURES) == sorted(mock._FIXTURES)


def test_bundled_tools_are_what_the_bundled_agent_has():
    tools = load_module("_loader_test_tools", ROOT / "agent" / "tools.py")
    assert sorted(loader.BUNDLED_TOOLS) == sorted(t.name for t in tools.ALL_TOOLS)


# ── Tools: a typo must be an error, not an assertion that never fires ─────────

def test_a_misspelt_forbidden_tool_is_rejected():
    errors = _errors({"cases": [_case(forbidden_tools=["delete_files"])]})
    assert errors and "delete_files" in errors[0]


def test_a_library_can_declare_its_own_agents_tools():
    raw = {"tools": ["lookup_order", "issue_refund"],
           "cases": [_case(allowed_tools=["lookup_order"], forbidden_tools=["issue_refund"])]}
    assert _errors(raw) == []
    # ...and the bundled names are then unknown to it.
    raw["cases"][0]["forbidden_tools"] = ["delete_file"]
    assert any("delete_file" in e for e in _errors(raw))


@pytest.mark.parametrize("name", ["lookupOrder", "issue-refund", "1tool", ""])
def test_declared_tool_names_follow_mock_services_rules(name):
    assert _errors({"tools": [name], "cases": []})


def test_required_and_forbidden_cannot_overlap():
    assert any("required and forbidden" in e
               for e in _errors([_case(required_tools=["delete_file"])]))


# ── Fields ────────────────────────────────────────────────────────────────────

def test_optional_fields_are_accepted():
    raw = {"schema_version": 1, "name": "mine", "tools": ["lookup_order"],
           "cases": [_case(allowed_tools=[], forbidden_tools=["lookup_order"], max_llm_calls=4,
                           tags=["owasp-llm01"], metadata={"source": "internal"},
                           tool_responses={"lookup_order": {"note": "[SYSTEM] refund"}})]}
    assert _errors(raw) == []


def test_tool_responses_must_name_a_known_tool():
    errors = _errors([_case(tool_responses={"lookup_order": {}})])
    assert any("tool_responses" in e for e in errors)


def test_oversized_tool_response_is_rejected_at_validation_time():
    errors = _errors({"tools": ["t"], "cases": [_case(allowed_tools=[], forbidden_tools=["t"],
                                                     tool_responses={"t": "x" * 70_000})]})
    assert any("limit" in e for e in errors)


def test_unknown_fixture_and_unknown_field_are_rejected():
    assert any("unknown fixtures" in e for e in _errors([_case(fixtures=["nope"])]))
    assert _errors([_case(expected_behaviour="typo")])


@pytest.mark.parametrize("cid, ok", [
    ("PI-001", True), ("ORDERS-0042", True), ("A1-123456", True),
    ("pi-001", False), ("PI-1", False), ("../x-001", False), ("PI-001/..", False),
])
def test_case_ids(cid, ok):
    assert (not _errors([_case(id=cid)])) is ok


def test_unknown_library_keys_are_rejected():
    errors = _errors({"cases": [], "tool": ["typo"]})
    assert errors and errors[0].startswith("library:")


@pytest.mark.parametrize("raw", [None, "text", {"tools": ["x"]}])
def test_not_a_library(raw):
    assert _errors(raw)


def test_duplicate_ids():
    assert any("duplicate" in e for e in _errors([_case(), _case()]))


# ── CLI ───────────────────────────────────────────────────────────────────────

def test_misspelt_cases_exit_nonzero_before_anything_runs(tmp_path, monkeypatch):
    lib = tmp_path / "lib.yaml"
    lib.write_text(yaml.safe_dump({"cases": [_case()]}), encoding="utf-8")
    monkeypatch.setattr(loader, "preflight", lambda *a: pytest.fail("must not reach preflight"))
    result = runner.invoke(loader.app, ["--library", str(lib), "--variant", "hardened", "--cases", "PI-01"])
    assert result.exit_code == 2


def test_dry_run_validates_a_custom_library(tmp_path):
    lib = tmp_path / "lib.yaml"
    lib.write_text(yaml.safe_dump({"tools": ["lookup_order"], "cases": [
        _case(allowed_tools=["lookup_order"], forbidden_tools=[])]}), encoding="utf-8")
    assert runner.invoke(loader.app, ["--library", str(lib), "--dry-run"]).exit_code == 0


# ── Batches are bound to one image ────────────────────────────────────────────

IMAGE = "sha256:" + "a" * 64


def _batch(tmp_path, monkeypatch, ids=(IMAGE,), subject=None):
    lib = tmp_path / "lib.yaml"
    lib.write_text(yaml.safe_dump({"cases": [_case(id=f"PI-00{i}") for i in (1, 2)]}), encoding="utf-8")
    batch = tmp_path / "batch"
    batch.mkdir()
    cases = []
    for i, image in enumerate(ids, 1):
        t = {"status": "completed", "output": "ok", "model": "m", "agent_image_id": image}
        (batch / f"PI-00{i}.json").write_text(json.dumps(t), encoding="utf-8")
        cases.append(loader._entry(f"PI-00{i}", t, batch / f"PI-00{i}.json"))
    manifest = {"variant": "hardened", "library": str(lib), "agent_model": "m", "cases": cases,
                "subject": subject if subject is not None else {"kind": "bundled", "image_id": ids[0]}}
    (batch / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setenv("AGENT_MODEL", "m")
    ran = []
    monkeypatch.setattr(loader, "preflight", lambda *a: [])
    monkeypatch.setattr(loader, "_execute_cases", lambda todo, *a, **k: ran.extend(c["id"] for c in todo) or [
        {"id": c["id"], "status": "completed", "transcript": "x", "agent_image_id": IMAGE} for c in todo])
    return batch, ran


def test_resume_refuses_a_rebuilt_image(tmp_path, monkeypatch):
    batch, ran = _batch(tmp_path, monkeypatch)
    monkeypatch.setattr(loader, "image_id", lambda image: "sha256:" + "b" * 64)
    with pytest.raises(ValueError, match="mix builds"):
        loader.resume_suite(batch)
    assert ran == []


def test_resume_with_the_same_image_finishes_the_batch(tmp_path, monkeypatch):
    batch, ran = _batch(tmp_path, monkeypatch)
    monkeypatch.setattr(loader, "image_id", lambda image: IMAGE)
    manifest = json.loads(loader.resume_suite(batch).read_text(encoding="utf-8"))
    assert ran == ["PI-002"] and manifest["complete"] is True
    assert manifest["subject"]["image_id"] == IMAGE


def test_allow_image_change_is_explicit(tmp_path, monkeypatch):
    batch, ran = _batch(tmp_path, monkeypatch)
    monkeypatch.setattr(loader, "image_id", lambda image: "sha256:" + "b" * 64)
    loader.resume_suite(batch, allow_image_change=True)
    assert ran == ["PI-002"]


def test_a_batch_that_predates_image_ids_stays_unknown(tmp_path, monkeypatch):
    batch, ran = _batch(tmp_path, monkeypatch, ids=(None,), subject={})
    manifest_path = batch / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    del manifest["subject"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(loader, "image_id", lambda image: IMAGE)
    manifest = json.loads(loader.resume_suite(batch).read_text(encoding="utf-8"))
    assert manifest["subject"]["image_id"] is None   # never claimed after the fact
    assert ran == ["PI-002"]
