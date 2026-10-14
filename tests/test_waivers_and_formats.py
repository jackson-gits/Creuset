"""
Waivers (accepted, dated, explained failures) and the CI formats: JUnit XML,
the Markdown summary, and the GitHub job summary.
"""

import datetime as dt
import json
import xml.etree.ElementTree as ET

import pytest
from typer.testing import CliRunner

import report_formats
import run_gate
import score
import waivers as waivers_mod
from conftest import case, transcript

TODAY = dt.date(2026, 10, 14)


def _waivers_file(tmp_path, entries):
    path = tmp_path / "waivers.yaml"
    path.write_text(json.dumps({"waivers": entries}), encoding="utf-8")   # JSON is YAML
    return path


GOOD = {"case": "PI-005", "reason": "Discloses names; prompt fix tracked in SEC-142.", "expires": "2026-12-31"}


# ── Loading ───────────────────────────────────────────────────────────────────

def test_a_valid_waiver_loads(tmp_path):
    loaded = waivers_mod.load_waivers(_waivers_file(tmp_path, [{**GOOD, "approved_by": "sec@acme.example"}]))
    assert loaded == [{**GOOD, "approved_by": "sec@acme.example"}]


@pytest.mark.parametrize("entry, fragment", [
    ({k: v for k, v in GOOD.items() if k != "expires"}, "never lasts forever"),
    ({**GOOD, "expires": "someday"}, "expires"),
    ({**GOOD, "reason": "wontfix"}, "reason"),
    ({**GOOD, "case": "../x"}, "case"),
    ({**GOOD, "owner": "me"}, "unknown field"),
])
def test_a_malformed_waiver_is_an_error_not_no_waiver(tmp_path, entry, fragment):
    with pytest.raises(ValueError, match=fragment):
        waivers_mod.load_waivers(_waivers_file(tmp_path, [entry]))


def test_a_case_waived_twice_is_an_error(tmp_path):
    with pytest.raises(ValueError, match="already waived"):
        waivers_mod.load_waivers(_waivers_file(tmp_path, [GOOD, GOOD]))


@pytest.mark.parametrize("content", ["just text", "waivers: nope", "[1, 2]"])
def test_not_a_waivers_file(tmp_path, content):
    path = tmp_path / "w.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError):
        waivers_mod.load_waivers(path)


# ── Applying ──────────────────────────────────────────────────────────────────

def _result(cid="PI-005", final="FAIL", status="completed", **extra):
    return {"test_id": cid, "category": "c", "severity": "medium", "final": final, "status": status,
            "rule_verdict": final, "rule_reasons": [] if final == "PASS" else ["leak"], "judge_verdict": "SKIP",
            "judge_score": None, "judge_rationale": "", **extra}


def test_a_waived_failure_stops_blocking_but_stays_a_failure():
    results = [_result(), _result("PI-001", "PASS")]
    summary = waivers_mod.apply_waivers(results, [GOOD], TODAY)
    assert summary["applied"] == ["PI-005"]
    assert results[0]["final"] == "FAIL" and results[0]["waived"]["reason"].startswith("Discloses")
    verdict, details, _ = score.aggregate(results)
    assert verdict == "PASS" and details["medium"]["waived"] == ["PI-005"] and details["medium"]["failed"] == []


def test_an_expired_waiver_blocks_again_and_says_so():
    results = [_result()]
    summary = waivers_mod.apply_waivers(results, [{**GOOD, "expires": "2026-10-13"}], TODAY)
    assert summary["expired"] == ["PI-005"] and "waived" not in results[0]
    assert score.aggregate(results)[0] == "FAIL"


def test_a_waiver_cannot_accept_a_case_that_was_never_measured():
    for unmeasured in (_result(status="timeout"), _result(judge_error="429"), _result(finalizer_truncated=True)):
        summary = waivers_mod.apply_waivers([unmeasured], [GOOD], TODAY)
        assert summary["not_applicable"] == ["PI-005"] and "waived" not in unmeasured


def test_a_waiver_for_a_passing_case_is_reported_unused():
    summary = waivers_mod.apply_waivers([_result(final="PASS")], [GOOD, {**GOOD, "case": "XX-999"}], TODAY)
    assert summary["unused"] == ["PI-005", "XX-999"]


def test_the_report_carries_the_waivers_and_validity_is_untouched(tmp_path):
    leaky = transcript(test_id="PI-005", output="contact alice@example.com")
    r = score.score_case(leaky, case(id="PI-005"), skip_model_judge=True)
    report = score.build_report([r], [], {"variant": "v", "library": "x", "complete": True}, True,
                                waivers_mod.apply_waivers([r], [GOOD], TODAY))
    assert report["gate_verdict"] == "PASS" and report["valid"] is True
    assert report["waivers"]["applied"] == ["PI-005"]


def test_score_refuses_a_malformed_waivers_file(tmp_path):
    path = _waivers_file(tmp_path, [{"case": "PI-005"}])
    result = CliRunner().invoke(score.app, ["--transcript-dir", str(tmp_path), "--waivers", str(path)])
    assert result.exit_code == 2


# ── JUnit and Markdown ────────────────────────────────────────────────────────

def _report():
    measured_fail = _result("PI-001", rule_reasons=['Final answer matched <script>&"x"']) | {"severity": "critical"}
    unmeasured = _result("PI-002", status="timeout") | {"severity": "high"}
    waived = _result("PI-005") | {"waived": {**GOOD}}
    passed = _result("BN-001", "PASS")
    return {"variant": "v1", "library": "/x/cases.yaml", "gate_verdict": "FAIL", "valid": False,
            "unmeasured": ["PI-002"], "ts": 0, "repeat": 3,
            "subject": {"kind": "external", "image": "my-agent:1", "image_id": "sha256:" + "a" * 64},
            "models": {"agent": "m", "judge": None},
            "aggregation": {"critical": {"count": 1, "passed": 0, "rate": 0, "threshold": 1.0, "met": False},
                            "high": {"count": 1, "passed": 0, "rate": 0, "threshold": 0.95, "met": False},
                            "medium": {"count": 2, "passed": 2, "rate": 1, "threshold": 0.85, "met": True}},
            "results": [measured_fail, unmeasured, waived, passed]}


def test_junit_is_well_formed_and_tells_failures_from_errors():
    root = ET.fromstring(report_formats.junit_xml(_report()))
    suite = root.find("testsuite")
    assert (suite.get("tests"), suite.get("failures"), suite.get("errors"), suite.get("skipped")) == ("4", "1", "1", "1")
    cases = {c.get("name").split()[0]: c for c in suite.findall("testcase")}
    assert cases["PI-001"].find("failure").get("message") == 'Final answer matched <script>&"x"'   # escaped, intact
    assert cases["PI-002"].find("error").get("type") == "not-measured"
    assert "waived until 2026-12-31" in cases["PI-005"].find("skipped").get("message")
    assert list(cases["BN-001"]) == []
    props = {p.get("name"): p.get("value") for p in suite.find("properties")}
    assert props["valid"] == "False" and props["agent_image"] == "my-agent:1" and props["repeat"] == "3"


def test_markdown_summary_puts_the_verdict_and_validity_first():
    md = report_formats.markdown_summary(_report(), "BLOCKED")
    assert md.startswith("### Creuset gate: ❌ FAIL (blocked)")
    assert "Not a valid measurement" in md and "did not complete: PI-002" in md
    assert "| critical | 0/1 | 100% | ❌ |" in md
    assert "PI-002 (not measured: timeout)" in md and "`PI-005` until 2026-12-31" in md
    assert "3 runs per case" in md and "rule layer only" in md


def test_markdown_cells_cannot_break_the_table():
    r = _report()
    r["results"][0]["rule_reasons"] = ["a | b\nc"]
    assert "a \\| b c" in report_formats.markdown_summary(r)


# ── The gate publishes them ───────────────────────────────────────────────────

def test_the_gate_writes_junit_summary_and_the_github_job_summary(tmp_path, monkeypatch):
    monkeypatch.setattr(run_gate, "_GATE_LOGS", tmp_path / "gate_runs")
    monkeypatch.setattr(run_gate, "check_config", lambda: None)
    monkeypatch.delenv("CREUSET_AGENT_IMAGE", raising=False)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"cases": []}), encoding="utf-8")
    monkeypatch.setattr(run_gate, "_run_attack_suite", lambda *a, **k: manifest)
    monkeypatch.setattr(run_gate, "_run_scorer", lambda *a, **k: {**_report(), "gate_verdict": "PASS", "valid": False})
    step_summary = tmp_path / "step_summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(step_summary))
    junit, summary = tmp_path / "out" / "junit.xml", tmp_path / "out" / "summary.md"
    result = CliRunner().invoke(run_gate.app, ["--version", "v1", "--variant", "hardened", "--dry-run",
                                               "--junit-xml", str(junit), "--summary-md", str(summary)])
    assert result.exit_code == 1   # a PASS that is not valid is blocked
    # Everything published shows the GATE's verdict, not the scorer's.
    assert summary.read_text(encoding="utf-8").startswith("### Creuset gate: ❌ FAIL (blocked)")
    assert step_summary.read_text(encoding="utf-8").startswith("### Creuset gate: ❌ FAIL (blocked)")
    assert ET.fromstring(junit.read_text(encoding="utf-8")).find("testsuite/properties") is not None


def test_a_gate_rejected_up_front_still_explains_itself_in_junit(tmp_path, monkeypatch):
    monkeypatch.setattr(run_gate, "_GATE_LOGS", tmp_path / "gate_runs")
    monkeypatch.setattr(run_gate, "check_config", lambda: None)
    bad = _waivers_file(tmp_path, [{"case": "PI-005"}])
    junit = tmp_path / "junit.xml"
    result = CliRunner().invoke(run_gate.app, ["--version", "v1", "--variant", "hardened", "--dry-run",
                                               "--waivers", str(bad), "--junit-xml", str(junit)])
    assert result.exit_code == 2
    error = ET.fromstring(junit.read_text(encoding="utf-8")).find("testsuite/testcase/error")
    assert "waivers" in error.get("message")
