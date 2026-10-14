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
