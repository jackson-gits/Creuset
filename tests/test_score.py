"""Aggregation and report validity: nothing may pass vacuously.

Also the report v1 contract: a batch scores the same wherever it lives, legacy
manifests and reports keep working, and the exit code says whether a verdict is
a measurement.
"""

import hashlib
import json
import shutil
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

import contract
import score
from conftest import ROOT, case, load_module, transcript
from score import aggregate, build_report, score_case

ATTACKS = ROOT / "attacks" / "attack_library.yaml"

# What every report carried before v1. ui/app.py, evaluate/run_eval.py,
# gate/run_gate.py and the published reports rely on these names and meanings.
LEGACY_REPORT_KEYS = {"judge_errors", "truncated_finalizer", "unmeasured", "batch_complete", "valid", "ts",
                      "variant", "library", "models", "gate_verdict", "aggregation", "by_category",
                      "coverage", "results", "judge_probes"}
LEGACY_RESULT_KEYS = {"test_id", "category", "severity", "transcript", "judge_error", "rule_verdict",
                      "rule_reasons", "rule_checks", "evidence", "judge_verdict", "judge_score",
                      "judge_rationale", "final", "status", "finalizer_truncated", "output_preview"}
V1_KEYS = {"schema_version", "kind", "library_info", "subject", "config", "provenance", "checks_skipped"}


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


# ── v1 output_truncated alias ─────────────────────────────────────────────────

def test_v1_output_truncated_fails_the_case_and_invalidates_the_report():
    # A v1 agent says output_truncated, not finalizer_truncated. complete_answer
    # FAILed it, but the report stayed valid: a truncated answer quoted as a result.
    r = score_case(transcript(output_truncated=True), case(), skip_model_judge=True)
    assert r["final"] == "FAIL"
    assert r["finalizer_truncated"] is True
    report = build_report([r], [], {"variant": "v", "library": "x", "complete": True}, skip_model_judge=True)
    assert report["truncated_finalizer"] == ["PI-001"]
    assert report["valid"] is False


@pytest.mark.parametrize("fields", [{}, {"finalizer_truncated": True}, {"output_truncated": True},
                                    {"output_truncated": False, "finalizer_truncated": True},
                                    {"output_truncated": 0}, {"finalizer_truncated": None}])
def test_truncation_alias_matches_the_contract(fields):
    assert score._output_truncated(fields) is contract.output_truncated(fields)


# ── Batches on disk ───────────────────────────────────────────────────────────

def _library_doc(cases, header=None):
    doc = {"cases": cases}
    return {"library": header, **doc} if header else doc


def _write_batch(folder: Path, transcripts, *, cases=None, header=None, manifest_extra=None,
                 transcript_paths=None, snapshot=True) -> Path:
    """A manifest-v1 batch as attacks/loader.py writes it: relative transcript
    paths and a library snapshot inside the folder."""
    folder.mkdir(parents=True)
    cases = cases or [case(id="TT-001"), case(id="TT-002", severity="high")]
    raw = yaml.safe_dump(_library_doc(cases, header), sort_keys=False).encode("utf-8")
    if snapshot:
        (folder / "library.yaml").write_bytes(raw)
    entries = []
    for cid, t in transcripts.items():
        (folder / f"{cid}.json").write_text(json.dumps(t), encoding="utf-8")
        entries.append({"id": cid, "status": t.get("status"),
                        "transcript": (transcript_paths or {}).get(cid, f"{cid}.json"),
                        "agent_model": "test-model", "agent_image_id": "sha256:abc", "elapsed_seconds": 1.0})
    manifest = {
        "schema_version": 1, "ts": 1, "variant": "hardened",
        "library": "attacks/team_cases.yaml", "library_sha256": hashlib.sha256(raw).hexdigest(),
        "library_snapshot": "library.yaml" if snapshot else None, "kind": "adversarial",
        "categories": None, "selected_ids": None, "tags": None,
        "agent_model": "test-model", "agent_image": "team/agent:1", "agent_image_id": "sha256:abc",
        "git": {"sha": "0" * 40, "dirty": False}, "case_count": len(entries), "complete": True,
        "cases": entries, "resumes": [],
        **(manifest_extra or {}),
    }
    path = folder / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


def _clean_and_leaky():
    return {"TT-001": transcript(test_id="TT-001"),
            "TT-002": transcript(test_id="TT-002", output="Sure: alice@example.com")}


def _verdicts(report):
    return {r["test_id"]: r["final"] for r in report["results"]}


@pytest.fixture(autouse=True)
def _no_ambient_canary_override(monkeypatch):
    monkeypatch.delenv("CREUSET_CANARY", raising=False)


def _posix(path: str) -> str:
    return path.replace("\\", "/")  # a path outside the checkout is recorded natively


@pytest.mark.parametrize("snapshot", [True, False])
def test_relocated_batch_scores_the_same_as_in_place(tmp_path, monkeypatch, snapshot):
    # The cwd is neither batch folder: relative paths must resolve against the
    # manifest, not wherever the scorer happens to run. Without a snapshot the
    # library is recorded by absolute path, as for a library outside the repo;
    # before manifest-relative paths that variant scored every case missing.
    monkeypatch.chdir(tmp_path)
    library = tmp_path / "team_cases.yaml"
    library.write_text(yaml.safe_dump({"cases": [case(id="TT-001"), case(id="TT-002", severity="high")]}),
                       encoding="utf-8")
    extra = None if snapshot else {"library": str(library), "library_snapshot": None,
                                   "library_sha256": hashlib.sha256(library.read_bytes()).hexdigest()}
    manifest = _write_batch(tmp_path / "logs" / "runs" / "b1", _clean_and_leaky(), snapshot=snapshot,
                            manifest_extra=extra)
    in_place = score.score_manifest(manifest, skip_model_judge=True)

    moved = Path(shutil.move(str(manifest.parent), str(tmp_path / "downloaded" / "artifact")))
    relocated = score.score_manifest(moved / "manifest.json", skip_model_judge=True)

    assert _verdicts(in_place) == _verdicts(relocated) == {"TT-001": "PASS", "TT-002": "FAIL"}
    assert in_place["gate_verdict"] == relocated["gate_verdict"] == "FAIL"
    assert in_place["valid"] is relocated["valid"] is True
    assert relocated["coverage"]["missing"] == [] and relocated["unmeasured"] == []
    assert relocated["library_info"]["source"] == ("snapshot" if snapshot else "recorded")
    assert relocated["library_info"]["matches_recorded"] is True
    assert all(_posix(r["transcript"]).endswith(f"artifact/{r['test_id']}.json") for r in relocated["results"])


# Roots that exist on no machine. The published batches really were written
# under D:\projects\Creuset, which exists on the owner's machine.
_GONE_WINDOWS = r"Z:\creuset-test-gone\Creuset"
_GONE_POSIX = "/creuset-test-gone/Creuset"


@pytest.mark.parametrize("root, sep", [(_GONE_WINDOWS, "\\"), (_GONE_POSIX, "/")])
def test_legacy_absolute_manifest_falls_back_to_its_folder_and_the_repo_library(tmp_path, root, sep):
    # Exactly what loader.py wrote before manifest v1: no schema_version, no
    # snapshot, absolute paths from the machine that ran it.
    recorded_dir = sep.join([root, "logs", "runs", "20260920-054506_hardened_attack_library"])
    library = sep.join([root, "attacks", "attack_library.yaml"])
    folder = tmp_path / "20260920-054506_hardened_attack_library"
    folder.mkdir()
    t = transcript(test_id="PI-001")
    (folder / "PI-001.json").write_text(json.dumps(t), encoding="utf-8")
    manifest = {"ts": 1, "variant": "hardened", "library": library, "categories": None,
                "selected_ids": ["PI-001"], "agent_model": "openai/gpt-oss-20b", "case_count": 1,
                "complete": True,
                "cases": [{"id": "PI-001", "status": "completed", "transcript": f"{recorded_dir}{sep}PI-001.json",
                           "agent_model": "openai/gpt-oss-20b", "elapsed_seconds": 3.2}]}
    (folder / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    report = score.score_manifest(folder / "manifest.json", skip_model_judge=True)

    expected = score_case(t, next(c for c in score.load_library(ATTACKS) if c["id"] == "PI-001"),
                          skip_model_judge=True)
    assert report["coverage"]["missing"] == []
    assert report["results"][0]["status"] == "completed"
    assert report["results"][0]["final"] == expected["final"]
    assert report["results"][0]["rule_checks"] == expected["rule_checks"]
    assert report["library_info"]["source"] == "repo_fallback"
    assert report["library_info"]["path"] == "attacks/attack_library.yaml"
    assert report["library_info"]["matches_recorded"] is None  # nothing was recorded to compare
    assert report["library"] == library  # the old key keeps what the manifest said
    assert report["kind"] == "adversarial"
    assert report["valid"] is True


def test_legacy_absolute_path_that_still_exists_is_used_as_recorded(tmp_path):
    # A batch scored on the machine that wrote it, from a copied manifest.
    original = tmp_path / "original"
    original.mkdir()
    (original / "TT-001.json").write_text(json.dumps(transcript(test_id="TT-001")), encoding="utf-8")
    manifest = _write_batch(tmp_path / "copy", {}, cases=[case(id="TT-001")])
    m = json.loads(manifest.read_text(encoding="utf-8"))
    m["cases"] = [{"id": "TT-001", "status": "completed", "transcript": str(original / "TT-001.json")}]
    manifest.write_text(json.dumps(m), encoding="utf-8")
    report = score.score_manifest(manifest, skip_model_judge=True)
    assert report["results"][0]["status"] == "completed"
    assert report["valid"] is True


def test_a_relative_transcript_path_cannot_leave_the_batch(tmp_path):
    # The manifest is data. Outside the batch sits a leaky transcript; inside,
    # under the case's own name, a clean one. Only the inside one may be read.
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "TT-001.json").write_text(json.dumps(transcript(test_id="TT-001", output="alice@example.com")),
                                         encoding="utf-8")
    manifest = _write_batch(tmp_path / "batch", {"TT-001": transcript(test_id="TT-001")},
                            cases=[case(id="TT-001")], transcript_paths={"TT-001": "../outside/TT-001.json"})
    report = score.score_manifest(manifest, skip_model_judge=True)
    assert _verdicts(report) == {"TT-001": "PASS"}
    assert "outside" not in report["results"][0]["transcript"]


def test_a_snapshot_path_cannot_leave_the_batch(tmp_path):
    evil = tmp_path / "evil.yaml"
    evil.write_text(yaml.safe_dump({"cases": [case(id="TT-001", forbidden_output_patterns=["Here"])]}),
                    encoding="utf-8")
    real = tmp_path / "real.yaml"
    real.write_text(yaml.safe_dump({"cases": [case(id="TT-001")]}), encoding="utf-8")
    manifest = _write_batch(tmp_path / "batch", {"TT-001": transcript(test_id="TT-001")},
                            cases=[case(id="TT-001")], snapshot=False,
                            manifest_extra={"library_snapshot": "../evil.yaml", "library": str(real),
                                            "library_sha256": None})
    report = score.score_manifest(manifest, skip_model_judge=True)
    assert report["library_info"]["source"] == "recorded"
    assert _verdicts(report) == {"TT-001": "PASS"}


def test_an_unreadable_transcript_is_missing_not_a_crash(tmp_path):
    manifest = _write_batch(tmp_path / "batch", _clean_and_leaky())
    (manifest.parent / "TT-001.json").write_text("{ half a transcr", encoding="utf-8")
    report = score.score_manifest(manifest, skip_model_judge=True)
    r = next(r for r in report["results"] if r["test_id"] == "TT-001")
    assert r["status"] == "missing" and r["final"] == "FAIL"
    assert "unreadable" in r["rule_reasons"][0]
    assert report["coverage"]["missing"] == ["TT-001"]
    assert report["valid"] is False


def test_a_changed_library_without_snapshot_is_flagged(tmp_path):
    lib = tmp_path / "lib.yaml"
    lib.write_text(yaml.safe_dump({"cases": [case(id="TT-001")]}), encoding="utf-8")
    manifest = _write_batch(tmp_path / "batch", {"TT-001": transcript(test_id="TT-001")},
                            cases=[case(id="TT-001")], snapshot=False,
                            manifest_extra={"library": str(lib), "library_sha256": "0" * 64,
                                            "library_snapshot": None})
    report = score.score_manifest(manifest, skip_model_judge=True)
    assert report["library_info"]["matches_recorded"] is False
    assert report["library_info"]["sha256"] == hashlib.sha256(lib.read_bytes()).hexdigest()


def test_tagged_batch_is_scored_against_its_tagged_cases_only(tmp_path):
    # loader.py --tag smoke runs the tagged cases; scoring the whole library
    # counted every untagged case as missing, i.e. FAIL and not valid.
    cases = [case(id="TT-001", tags=["smoke"]), case(id="TT-002"),
             case(id="JM-001", probe="judge", synthetic_transcript={})]
    manifest = _write_batch(tmp_path / "batch", {"TT-001": transcript(test_id="TT-001")}, cases=cases,
                            manifest_extra={"tags": ["smoke"]})
    report = score.score_manifest(manifest, skip_model_judge=True)
    assert [r["test_id"] for r in report["results"]] == ["TT-001"]
    assert report["valid"] is True and report["gate_verdict"] == "PASS"


# ── Report v1 fields ──────────────────────────────────────────────────────────

def test_v1_report_adds_fields_and_keeps_every_legacy_one(tmp_path):
    manifest = _write_batch(tmp_path / "batch", _clean_and_leaky())
    report = score.score_manifest(manifest, skip_model_judge=True)

    assert LEGACY_REPORT_KEYS | V1_KEYS <= set(report)
    assert all(LEGACY_RESULT_KEYS <= set(r) for r in report["results"])
    # Legacy meanings: `library` is what the manifest recorded, `models` as before.
    assert report["library"] == "attacks/team_cases.yaml"
    assert report["variant"] == "hardened"
    assert report["models"] == {"agent": "test-model", "judge": None}
    assert report["batch_complete"] is True

    assert report["schema_version"] == 1
    assert report["kind"] == "adversarial"
    snapshot = manifest.parent / "library.yaml"
    assert report["library_info"]["sha256"] == hashlib.sha256(snapshot.read_bytes()).hexdigest()
    assert _posix(report["library_info"]["path"]).endswith("batch/library.yaml")
    assert report["subject"] == {"variant": "hardened", "agent_model": "test-model",
                                 "agent_image": "team/agent:1", "agent_image_id": "sha256:abc"}
    config = report["config"]
    assert config["thresholds"] == score.THRESHOLDS
    assert config["judge_model"] is None and config["judge_samples"] is None  # no judge ran
    assert set(report["provenance"]) >= {"creuset_version", "git_sha"}
    assert report["provenance"]["batch_git"] == {"sha": "0" * 40, "dirty": False}
    assert report["checks_skipped"] == []
    json.dumps(report)  # serialisable as is


def test_judge_settings_are_recorded_without_credentials(monkeypatch):
    monkeypatch.setenv("JUDGE_API_BASE", "https://user:s3cret@api.groq.com:443/openai/v1")
    r = score_case(transcript(), case(), skip_model_judge=True)
    report = build_report([r], [], {"variant": "v", "library": "x"}, skip_model_judge=False)
    config = report["config"]
    assert config["judge_base_host"] == "api.groq.com:443"
    assert config["judge_model"] == score.JUDGE_MODEL == report["models"]["judge"]
    assert config["judge_samples"] == score.model_judge._JUDGE_SAMPLES
    assert config["judge_seed"] == score.model_judge._JUDGE_SEED
    assert "s3cret" not in json.dumps(report)


def test_agent_settings_are_reported_only_when_uniform():
    a = transcript(harness_config={"AGENT_MAX_TOKENS": "400", "FINALIZER_MAX_TOKENS": "1024",
                                   "MAX_LLM_CALLS": "15"})
    b = transcript(harness_config={**a["harness_config"], "AGENT_MAX_TOKENS": "700"})
    r = [score_case(a, case(), skip_model_judge=True)]

    def settings(transcripts):
        return build_report(r, [], {}, True, transcripts=transcripts)["config"]["agent_settings"]

    assert settings([a, dict(a)]) == a["harness_config"]
    assert settings([a, b]) == "mixed"
    assert settings([a, transcript()]) == "mixed"  # one recorded nothing
    assert settings([transcript()]) is None


def test_subject_falls_back_to_what_the_transcripts_say():
    t = transcript(model="m1", variant="hardened", agent_image="team/agent:2", agent_image_id="sha256:def")
    r = [score_case(t, case(), skip_model_judge=True)]
    subject = build_report(r, [], {}, True, transcripts=[t, dict(t)])["subject"]
    assert subject == {"variant": "hardened", "agent_model": "m1", "agent_image": "team/agent:2",
                       "agent_image_id": "sha256:def"}
    assert build_report(r, [], {}, True, transcripts=[t, {**t, "model": "m2"}])["subject"]["agent_model"] == "mixed"


def test_skipped_rule_checks_are_listed(monkeypatch):
    monkeypatch.setenv("CREUSET_CANARY", "")
    r = score_case(transcript(), case(), skip_model_judge=True)
    report = build_report([r], [], {"variant": "v", "library": "x", "complete": True}, True)
    assert report["checks_skipped"] == ["canary"]
    assert report["valid"] is True  # a gap to show, not an unmeasured case


def test_kind_comes_from_manifest_then_header_then_file_name(tmp_path):
    lib_path = tmp_path / "refund_regressions.yaml"
    lib_path.write_text(yaml.safe_dump(_library_doc([case(id="TT-001")], {"schema_version": 1, "kind": "benign"})),
                        encoding="utf-8")
    declared = score.read_library(lib_path)
    assert score.report_kind({"kind": "adversarial"}, declared) == "adversarial"
    assert score.report_kind({"library": "refund_regressions.yaml"}, declared) == "benign"
    assert score.report_kind({"library": r"D:\x\benign_tasks.yaml"}) == "benign"
    assert score.report_kind({"library": "attacks/attack_library.yaml"}) == "adversarial"
    assert score.report_kind({}) is None


def test_bundled_libraries_declare_their_kind():
    assert score.read_library(ATTACKS).declared_kind == "adversarial"
    assert score.read_library(ROOT / "attacks" / "benign_tasks.yaml").declared_kind == "benign"


def test_v1_report_reads_the_same_in_the_results_browser(tmp_path, monkeypatch):
    from ui import app as ui_app
    monkeypatch.setattr(ui_app, "_LOGS", tmp_path)
    manifest = _write_batch(tmp_path / "runs" / "b", _clean_and_leaky(),
                            manifest_extra={"library": "attacks/benign_tasks.yaml", "kind": "benign"})
    report = score.score_manifest(manifest, skip_model_judge=True)
    path = tmp_path / "r.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    card = ui_app._report_card(path, report, "score report")
    assert card["library"] == "benign_tasks.yaml"
    assert card["kind"] == "benign" == report["kind"]
    assert card["layer"] == "rule only"
    assert card["valid"] is True and card["invalid_reasons"] == []


def test_judge_workers_default_to_one(monkeypatch):
    import dotenv
    monkeypatch.delenv("JUDGE_WORKERS", raising=False)
    monkeypatch.setattr(dotenv, "load_dotenv", lambda *a, **k: False)  # ignore a developer's .env
    fresh = load_module("_score_defaults", ROOT / "judge" / "score.py")
    assert fresh._JUDGE_WORKERS == 1


# ── CLI: exit codes, --json, --library ────────────────────────────────────────

def _cli(*args):
    return CliRunner().invoke(score.app, [str(a) for a in args])


def _said(stream: str) -> str:
    """Console text with rich's line wrapping undone."""
    return " ".join(stream.split())


@pytest.fixture
def no_judge_calls(monkeypatch):
    def refuse(*_a, **_k):
        raise AssertionError("the judge must not be called")
    monkeypatch.setattr(score, "run_model_judge", refuse)


def test_exit_0_for_a_valid_pass(tmp_path, no_judge_calls):
    manifest = _write_batch(tmp_path / "b", {"TT-001": transcript(test_id="TT-001"),
                                             "TT-002": transcript(test_id="TT-002")})
    out = tmp_path / "report.json"
    result = _cli("--manifest", manifest, "--skip-model-judge", "--output", out)
    assert result.exit_code == 0, result.output
    assert json.loads(out.read_text(encoding="utf-8"))["gate_verdict"] == "PASS"


def test_exit_1_for_a_valid_fail(tmp_path, no_judge_calls):
    manifest = _write_batch(tmp_path / "b", _clean_and_leaky())
    result = _cli("--manifest", manifest, "--skip-model-judge", "--output", tmp_path / "r.json")
    assert result.exit_code == 1, result.output


@pytest.mark.parametrize("damage", ["incomplete", "missing"])
def test_exit_3_for_an_invalid_report_whatever_the_verdict(tmp_path, no_judge_calls, damage):
    # The incomplete batch PASSes the gate on what did run; the one with a
    # missing transcript FAILs it. Neither verdict is a measurement.
    transcripts = {"TT-001": transcript(test_id="TT-001"), "TT-002": transcript(test_id="TT-002")}
    manifest = _write_batch(tmp_path / "b", transcripts,
                            manifest_extra={"complete": False} if damage == "incomplete" else None)
    if damage == "missing":
        (manifest.parent / "TT-002.json").unlink()
    out = tmp_path / "r.json"
    result = _cli("--manifest", manifest, "--skip-model-judge", "--output", out)
    assert result.exit_code == 3, result.output
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["valid"] is False


def test_exit_2_for_a_missing_manifest_without_a_traceback(tmp_path):
    result = _cli("--manifest", tmp_path / "nope.json", "--skip-model-judge", "--output", tmp_path / "r.json")
    assert result.exit_code == 2
    assert "Traceback" not in result.output and "No manifest" in _said(result.stderr)
    assert not (tmp_path / "r.json").exists()


@pytest.mark.parametrize("content", ["{not json", "[1, 2]", '{"schema_version": 2, "cases": []}',
                                     '{"cases": {"TT-001": 1}}'])
def test_exit_2_for_an_unusable_manifest(tmp_path, content):
    path = tmp_path / "manifest.json"
    path.write_text(content, encoding="utf-8")
    result = _cli("--manifest", path, "--skip-model-judge", "--output", tmp_path / "r.json")
    assert result.exit_code == 2, result.output
    assert "Traceback" not in result.output


def test_exit_2_when_the_library_cannot_be_found(tmp_path):
    manifest = _write_batch(tmp_path / "b", {"TT-001": transcript(test_id="TT-001")}, snapshot=False,
                            manifest_extra={"library": "attacks/no_such_library.yaml", "library_snapshot": None})
    result = _cli("--manifest", manifest, "--skip-model-judge", "--output", tmp_path / "r.json")
    assert result.exit_code == 2
    assert "cannot be found" in _said(result.stderr)


def test_exit_2_without_anything_to_score():
    assert _cli("--skip-model-judge").exit_code == 2


def test_exit_2_when_the_judge_is_not_configured(tmp_path, monkeypatch, no_judge_calls):
    # Without the up-front check every case failed closed on the same config
    # error: 26 identical judge failures and a report that read as detections.
    def not_configured():
        raise score.JudgeConfigError("JUDGE_MODEL is not set, and the judge has no default model.")
    monkeypatch.setattr(score, "check_config", not_configured)
    manifest = _write_batch(tmp_path / "b", _clean_and_leaky())
    result = _cli("--manifest", manifest, "--output", tmp_path / "r.json")
    assert result.exit_code == 2
    assert "JUDGE_MODEL is not set" in _said(result.stderr)
    assert not (tmp_path / "r.json").exists()


def test_library_is_refused_with_a_manifest(tmp_path):
    manifest = _write_batch(tmp_path / "b", _clean_and_leaky())
    result = _cli("--manifest", manifest, "--library", ATTACKS, "--skip-model-judge")
    assert result.exit_code == 2


def test_json_sends_the_report_to_stdout_and_the_rest_to_stderr(tmp_path, monkeypatch, no_judge_calls):
    monkeypatch.setattr(score, "_LOGS_DIR", tmp_path / "logs")
    manifest = _write_batch(tmp_path / "b", _clean_and_leaky())
    result = _cli("--manifest", manifest, "--skip-model-judge", "--json")
    assert result.exit_code == 1
    report = json.loads(result.stdout)
    assert report["schema_version"] == 1 and _verdicts(report) == {"TT-001": "PASS", "TT-002": "FAIL"}
    assert "Gate verdict" in result.stderr and "Gate verdict" not in result.stdout
    assert not (tmp_path / "logs").exists()  # no stray file without --output


def test_json_with_output_writes_the_same_report(tmp_path, no_judge_calls):
    manifest = _write_batch(tmp_path / "b", _clean_and_leaky())
    out = tmp_path / "r.json"
    result = _cli("--manifest", manifest, "--skip-model-judge", "--json", "--output", out)
    assert json.loads(result.stdout) == json.loads(out.read_text(encoding="utf-8"))


def test_transcript_lookup_in_a_given_library(tmp_path, no_judge_calls):
    lib = tmp_path / "team_cases.yaml"
    lib.write_text(yaml.safe_dump({"cases": [case(id="ACME-0001")]}), encoding="utf-8")
    t = tmp_path / "t.json"
    t.write_text(json.dumps(transcript(test_id="ACME-0001")), encoding="utf-8")
    out = tmp_path / "r.json"
    result = _cli("--transcript", t, "--library", lib, "--skip-model-judge", "--output", out)
    assert result.exit_code == 0, result.output
    report = json.loads(out.read_text(encoding="utf-8"))
    assert [r["test_id"] for r in report["results"]] == ["ACME-0001"]
    assert report["library_info"]["sha256"] == hashlib.sha256(lib.read_bytes()).hexdigest()
    assert report["kind"] == "adversarial"
    assert report["variant"] is None  # ad hoc: no manifest says which build this was


def test_transcript_with_an_unknown_case_is_exit_2(tmp_path):
    t = tmp_path / "t.json"
    t.write_text(json.dumps(transcript(test_id="ZZ-999")), encoding="utf-8")
    result = _cli("--transcript", t, "--skip-model-judge", "--output", tmp_path / "r.json")
    assert result.exit_code == 2
    assert "No results scored" in _said(result.stderr)


def test_transcript_dir_skips_unreadable_files(tmp_path, no_judge_calls):
    (tmp_path / "PI-001.json").write_text(json.dumps(transcript(test_id="PI-001")), encoding="utf-8")
    (tmp_path / "broken.json").write_text("{", encoding="utf-8")
    out = tmp_path / "out" / "r.json"
    result = _cli("--transcript-dir", tmp_path, "--skip-model-judge", "--output", out)
    assert result.exit_code in (0, 1), result.output
    report = json.loads(out.read_text(encoding="utf-8"))
    assert [r["test_id"] for r in report["results"]] == ["PI-001"]
    assert report["library"] == "attacks/attack_library.yaml"
