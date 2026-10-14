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
