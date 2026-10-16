"""Results browser: loopback-only, logs/-only, and a CSP behind the escaping."""

import pytest
from fastapi.testclient import TestClient

from ui import app as ui_app

local = TestClient(ui_app.app, base_url="http://127.0.0.1:8090")


def test_rebound_hostname_is_refused():
    # DNS rebinding: an attacker's page reaches 127.0.0.1 but under its own name.
    evil = TestClient(ui_app.app, base_url="http://attacker.example:8090")
    assert evil.get("/api/overview").status_code == 400


def test_index_carries_security_headers():
    resp = local.get("/")
    assert resp.status_code == 200
    csp = resp.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert resp.headers["x-content-type-options"] == "nosniff"


@pytest.mark.parametrize("path", ["../.env", "runs/../../.env", "/etc/passwd", "..\\.env"])
def test_report_path_cannot_escape_logs(path):
    assert local.get("/api/report", params={"path": path}).status_code in (403, 404)


@pytest.mark.parametrize("batch,case_id", [("..", "../.env"), ("../..", "README")])
def test_transcript_path_cannot_escape_logs(batch, case_id):
    assert local.get("/api/transcript", params={"batch": batch, "case": case_id}).status_code in (403, 404)


def test_overview_does_not_disclose_filesystem_root():
    assert "root" not in local.get("/api/overview").json()


def test_api_docs_are_off():
    assert local.get("/docs").status_code == 404


@pytest.mark.parametrize("recorded", [r"D:\projects\Creuset\attacks\attack_library.yaml",
                                      "/home/ci/Creuset/attacks/attack_library.yaml"])
def test_library_name_from_any_os(recorded):
    # Reports written on Windows must not show their full path when viewed elsewhere.
    assert ui_app._basename(recorded) == "attack_library.yaml"


def test_a_repeated_batch_lists_every_run_by_its_own_file(tmp_path, monkeypatch):
    """With --repeat, three rows of EX-001 must open three transcripts, not run 1 three times."""
    import json
    import ui.app as ui_app
    from fastapi.testclient import TestClient
    batch = tmp_path / "runs" / "b1"
    batch.mkdir(parents=True)
    entries = [{"id": "EX-001", "status": "completed"}, {"id": "EX-001", "status": "error", "sample": 2}]
    (batch / "manifest.json").write_text(json.dumps({"variant": "v", "cases": entries}), encoding="utf-8")
    monkeypatch.setattr(ui_app, "_LOGS", tmp_path)
    client = TestClient(ui_app.app, base_url="http://127.0.0.1:8090")
    runs = [c["run"] for c in client.get("/api/batch", params={"name": "b1"}).json()["cases"]]
    assert runs == ["EX-001", "EX-001.r2"]


def test_a_gate_report_says_what_was_tested(tmp_path, monkeypatch):
    """Subject, settings, box and the deployed slot: a number means little without them."""
    import json
    import ui.app as ui_app
    from fastapi.testclient import TestClient
    report = {"gate_verdict": "PASS", "valid": True, "results": [], "repeat": 3,
              "subject": {"kind": "bundled", "image": "creuset-agent:latest", "image_content": "sha256:ab"},
              "run_settings": {"AGENT_MAX_TOKENS": "1024"}, "sandbox": {"memory": "512m"},
              "contract_errors": ["EX-002"]}
    record = {"decision": "DEPLOYED", "version": "v1.1.0", "slot": "green",
              "tested_image_content": "sha256:ab", "score_report": report}
    (tmp_path / "gate_runs").mkdir()
    (tmp_path / "gate_runs" / "gate_1.json").write_text(json.dumps(record), encoding="utf-8")
    monkeypatch.setattr(ui_app, "_LOGS", tmp_path)
    client = TestClient(ui_app.app, base_url="http://127.0.0.1:8090")
    data = client.get("/api/report", params={"path": "gate_runs/gate_1.json"}).json()
    assert data["gate"]["slot"] == "green" and data["gate"]["tested_image_content"] == "sha256:ab"
    p = data["provenance"]
    assert p["repeat"] == 3 and p["run_settings"] == {"AGENT_MAX_TOKENS": "1024"}
    assert p["subject"]["image"] == "creuset-agent:latest" and p["contract_errors"] == ["EX-002"]
