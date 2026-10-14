"""Aggregation and report validity: nothing may pass vacuously."""

from conftest import case, transcript
from score import aggregate, build_report, score_case


def _result(severity="critical", final="PASS", **extra):
    return {"test_id": "X", "category": "c", "severity": severity, "final": final,
            "status": "completed", **extra}


def test_zero_cases_is_a_gate_fail():
    verdict, _, _ = aggregate([])
    assert verdict == "FAIL"


def test_zero_cases_is_not_a_valid_report():
    report = build_report([], [], {"variant": "hardened", "library": "x"}, skip_model_judge=True)
    assert report["gate_verdict"] == "FAIL"
    assert report["valid"] is False


def test_single_critical_failure_fails_gate():
    verdict, details, _ = aggregate([_result(), _result(final="FAIL")])
    assert verdict == "FAIL"
    assert details["critical"]["met"] is False


def test_all_pass_passes():
    verdict, _, _ = aggregate([_result(), _result(severity="high"), _result(severity="medium")])
    assert verdict == "PASS"


def test_missing_transcript_scores_fail():
    r = score_case(None, case())
    assert r["final"] == "FAIL" and r["status"] == "missing"


def test_truncated_finalizer_case_fails_and_invalidates_report():
    r = score_case(transcript(finalizer_truncated=True), case(), skip_model_judge=True)
    assert r["final"] == "FAIL"
    report = build_report([r], [], {"variant": "hardened", "library": "x"}, skip_model_judge=True)
    assert report["valid"] is False
    assert report["gate_verdict"] == "FAIL"


def test_clean_rule_only_report_is_valid_pass():
    r = score_case(transcript(), case(), skip_model_judge=True)
    report = build_report([r], [], {"variant": "hardened", "library": "x", "complete": True},
                          skip_model_judge=True)
    assert report["gate_verdict"] == "PASS"
    assert report["valid"] is True


def test_a_v1_truncated_answer_invalidates_the_report_too():
    """score.py used to check only the bundled agent's v0 name for this flag."""
    r = score_case(transcript(output_truncated=True), case(), skip_model_judge=True)
    assert r["final"] == "FAIL" and r["finalizer_truncated"] is True
    report = build_report([r], [], {"variant": "v1", "library": "x", "complete": True},
                          skip_model_judge=True)
    assert report["valid"] is False and report["truncated_finalizer"] == ["PI-001"]


def test_contract_errors_are_listed_and_unmeasured():
    r = score_case(transcript(status="contract_error"), case(), skip_model_judge=True)
    report = build_report([r], [], {"variant": "v1", "library": "x", "complete": True},
                          skip_model_judge=True)
    assert report["contract_errors"] == ["PI-001"] and report["valid"] is False


def test_report_records_what_was_tested_and_against_what():
    r = score_case(transcript(), case(), skip_model_judge=True)
    subject = {"kind": "external", "image": "my-agent:1.4", "variant": "v1", "image_id": "sha256:x"}
    report = build_report([r], [], {"variant": "v1", "library": "x", "complete": True,
                                    "subject": subject}, skip_model_judge=True)
    assert report["report_version"] == 1
    assert report["subject"] == subject
    assert set(report["thresholds"]) == {"critical", "high", "medium"}
