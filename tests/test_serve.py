"""
Live slots (agent/serve.py) and the compose file that deploys them.

A slot that cannot write logs/live_traffic still answers requests, but the
monitor then watches an empty directory and never rolls back. On native Linux
that was the default (the bind mount keeps the host owner; the slot ran as
10001) and serve.py swallowed the error, so nothing said so. These tests hold
the fix: /health is 503 while transcripts cannot be written, the first failure
reaches stderr, and compose runs the slots under a configurable uid with a
healthcheck that turns that 503 into `up --wait` failing.

The compose half also holds the slots' environment to the harness's: a slot
must run the configuration the gate tested.
"""

from __future__ import annotations

import http.server
import json
import os
import re
import shutil
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Dict, List, Mapping, Tuple

import pytest
import yaml
from fastapi.testclient import TestClient

import router
import run_test
from conftest import ROOT, load_module

COMPOSE_FILE = ROOT / "docker-compose.yml"


# ── serve.py ──────────────────────────────────────────────────────────────────

Calls = List[Tuple[Dict[str, Any], str, Any]]


@pytest.fixture
def serve_at(monkeypatch):
    """Import serve.py writing live traffic to `live_dir`, with run_scenario stubbed (no LLM, no mock world)."""

    def _load(live_dir: Path):
        monkeypatch.setenv("LIVE_TRAFFIC_DIR", str(live_dir))
        monkeypatch.setenv("SLOT", "blue")
        monkeypatch.setenv("AGENT_VARIANT", "hardened")
        monkeypatch.setenv("AGENT_VERSION", "v-test")
        monkeypatch.delenv("LIVE_MAX_ACTIONS", raising=False)
        serve = load_module("_serve_under_test", ROOT / "agent" / "serve.py")
        calls: Calls = []

        def fake_run_scenario(scenario, variant, run_id=None):
            calls.append((scenario, variant, run_id))
            return {"test_id": scenario["test_id"], "run_id": run_id, "variant": variant,
                    "status": "completed", "output": "Done.", "tool_calls": []}

        monkeypatch.setattr(serve, "run_scenario", fake_run_scenario)
        return serve, calls

    return _load


def _failures(err: str) -> List[str]:
    return [line for line in err.splitlines() if "cannot write live-traffic transcripts" in line]


def _transcripts(live: Path) -> List[Path]:
    return sorted(live.glob("*.json"))  # what monitor/watch.py reads


def test_health_reports_a_writable_live_traffic_dir(serve_at, tmp_path):
    live = tmp_path / "live"
    serve, _ = serve_at(live)
    with TestClient(serve.app) as client:
        resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "slot": "blue", "variant": "hardened", "version": "v-test",
                           "live_traffic_writable": True}
    # The probe leaves nothing behind, and never anything the monitor would read.
    assert list(live.iterdir()) == []


def test_health_is_503_when_live_traffic_cannot_be_written(serve_at, tmp_path, capsys):
    blocked = tmp_path / "live"
    blocked.write_text("a file where the directory should be", encoding="utf-8")
    serve, _ = serve_at(blocked)
    with TestClient(serve.app) as client:  # the startup probe runs here
        first, second = client.get("/health"), client.get("/health")
    for resp in (first, second):
        assert resp.status_code == 503  # so the healthcheck, and `up --wait`, fail
        body = resp.json()
        assert body["live_traffic_writable"] is False
        assert body["status"] == "unhealthy"
        assert "FileExistsError" in body["live_traffic_error"]
        assert {body["slot"], body["variant"], body["version"]} == {"blue", "hardened", "v-test"}
    # Logged once at startup with the fix, not once per healthcheck.
    failures = _failures(capsys.readouterr().err)
    assert len(failures) == 1
    assert str(blocked) in failures[0] and "CREUSET_UID" in failures[0]


def test_health_probes_even_without_a_startup_event(serve_at, tmp_path):
    # An embedding that never runs the lifespan must not read as healthy by default.
    blocked = tmp_path / "live"
    blocked.write_text("x", encoding="utf-8")
    serve, _ = serve_at(blocked)
    assert TestClient(serve.app).get("/health").status_code == 503


@pytest.mark.skipif(os.name == "nt" or os.geteuid() == 0,
                    reason="permission bits: POSIX only, and root ignores them")
def test_health_is_503_for_a_directory_owned_by_someone_else(serve_at, tmp_path):
    # The real Linux failure: the directory exists, the slot's uid may not write it.
    live = tmp_path / "live"
    live.mkdir()
    live.chmod(0o555)
    try:
        serve, _ = serve_at(live)
        with TestClient(serve.app) as client:
            resp = client.get("/health")
        assert resp.status_code == 503 and "PermissionError" in resp.json()["live_traffic_error"]
    finally:
        live.chmod(0o755)


def test_a_write_failure_is_surfaced_and_the_request_still_answered(serve_at, tmp_path, capsys):
    live = tmp_path / "live"
    serve, _ = serve_at(live)
    with TestClient(serve.app) as client:
        assert client.get("/health").status_code == 200
        shutil.rmtree(live)
        live.write_text("x", encoding="utf-8")  # the directory goes away after start-up

        answers = [client.post("/invoke", json={"input": f"Read reports/{n}.txt"}) for n in range(2)]
        health = client.get("/health")

    # Monitoring must never take the service down ...
    assert [a.status_code for a in answers] == [200, 200]
    assert all(a.json()["output"] == "Done." for a in answers)
    # ... but it is no longer silent: stderr once, and the healthcheck fails.
    assert len(_failures(capsys.readouterr().err)) == 1
    assert health.status_code == 503 and health.json()["live_traffic_writable"] is False


def test_a_fixed_directory_recovers_without_a_restart(serve_at, tmp_path, capsys):
    live = tmp_path / "live"
    live.write_text("x", encoding="utf-8")
    serve, _ = serve_at(live)
    with TestClient(serve.app) as client:
        assert client.get("/health").status_code == 503
        live.unlink()
        live.mkdir()  # e.g. the operator chowns or remounts it
        assert client.get("/health").status_code == 200
        assert client.post("/invoke", json={"input": "hello"}).status_code == 200
    assert "writable again" in capsys.readouterr().err
    assert len(_transcripts(live)) == 1


def test_a_second_outage_is_logged_again(serve_at, tmp_path, capsys):
    live = tmp_path / "live"
    serve, _ = serve_at(live)
    with TestClient(serve.app) as client:
        for _ in range(2):
            shutil.rmtree(live)
            live.write_text("x", encoding="utf-8")
            client.post("/invoke", json={"input": "hello"})  # fails: logged
            client.post("/invoke", json={"input": "hello"})  # still failing: not logged again
            live.unlink()
            live.mkdir()
            client.post("/invoke", json={"input": "hello"})  # recovered
    assert len(_failures(capsys.readouterr().err)) == 2


def test_invoke_writes_the_transcript_the_monitor_reads(serve_at, tmp_path):
    live = tmp_path / "live"
    serve, _ = serve_at(live)
    with TestClient(serve.app) as client:
        resp = client.post("/invoke", json={"input": "Read reports/summary.txt"})
    assert resp.status_code == 200
    (path,) = _transcripts(live)
    assert path.name.startswith("blue_")
    written = json.loads(path.read_text(encoding="utf-8"))
    assert written["slot"] == "blue" and written["version"] == "v-test"
    assert written["input"] == "Read reports/summary.txt" and isinstance(written["received_at"], float)
    assert resp.json() == {"request_id": resp.json()["request_id"], "slot": "blue", "version": "v-test",
                           "status": "completed", "output": "Done."}


def test_invoke_calls_run_scenario_exactly_as_before(serve_at, tmp_path):
    # The writability work wraps the agent; it must not change how it is run.
    serve, calls = serve_at(tmp_path / "live")
    with TestClient(serve.app) as client:
        request_id = client.post("/invoke", json={"input": "hi"}).json()["request_id"]
    assert calls == [({"test_id": f"LIVE-{request_id}", "input_payload": "hi", "max_actions": 8},
                      "hardened", f"live-blue-{request_id}")]


# ── docker-compose.yml ────────────────────────────────────────────────────────

_REF = re.compile(r"\$\{(\w+)(?:(:[-?])([^}]*))?\}")


def _interpolate(value: Any, env: Mapping[str, str]) -> str:
    """Compose's ${NAME}, ${NAME:-default} and ${NAME:?error}: empty counts as unset."""
    def one(m: re.Match) -> str:
        name, op, arg = m.group(1), m.group(2), m.group(3)
        got = env.get(name, "")
        if got or op is None:
            return got
        if op == ":?":
            raise LookupError(f"{name} is required: {arg}")
        return arg
    return _REF.sub(one, str(value))


@pytest.fixture(scope="module")
def compose() -> Dict[str, Any]:
    return yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))


SLOTS = ("agent-blue", "agent-green")
# Per test run in the harness; a slot makes its own run id per request.
_PER_RUN = {"CREUSET_RUN_ID", "CREUSET_TOOLS_URL"}
_HARNESS_INPUTS = ("AGENT_API_BASE", "AGENT_MODEL", "MAX_LLM_CALLS", "LLM_MAX_RETRIES", "AGENT_MAX_TOKENS",
                   "FINALIZER_MAX_TOKENS", "LLM_TIMEOUT_SECONDS")


@pytest.mark.parametrize("env", [
    pytest.param({}, id="defaults"),
    pytest.param({name: "" for name in _HARNESS_INPUTS}, id="empty-means-default"),
    pytest.param({"AGENT_API_BASE": "http://llm-proxy:11434/v1", "AGENT_MODEL": "test/model",
                  "MAX_LLM_CALLS": "7", "LLM_MAX_RETRIES": "2", "AGENT_MAX_TOKENS": "400",
                  "FINALIZER_MAX_TOKENS": "2048", "LLM_TIMEOUT_SECONDS": "33"}, id="configured"),
])
def test_slots_get_the_environment_the_gate_tested(compose, monkeypatch, env):
    for name in _HARNESS_INPUTS:
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    tested = {k: v for k, v in run_test._container_env("r1").items() if k not in _PER_RUN}
    if not env.get("AGENT_MODEL"):
        tested.pop("AGENT_MODEL")  # required by both: compose refuses to start without it
    for slot in SLOTS:
        deployed = compose["services"][slot]["environment"]
        assert set(tested) <= set(deployed), f"{slot} is missing {sorted(set(tested) - set(deployed))}"
        assert {k: _interpolate(deployed[k], env) for k in tested} == tested


def test_slots_run_as_a_configurable_uid_defaulting_to_the_images(compose):
    for slot in SLOTS:
        assert compose["services"][slot]["user"] == "${CREUSET_UID:-10001}:${CREUSET_GID:-10001}"
    assert _interpolate(compose["services"]["agent-blue"]["user"], {"CREUSET_UID": "1000"}) == "1000:10001"
    # The default must stay the user the image creates, or Docker Desktop users
    # (who never set CREUSET_UID) would run as a different uid than before.
    dockerfile = (ROOT / "agent" / "Dockerfile").read_text(encoding="utf-8")
    m = re.search(r"useradd\b[^\n]*?(?:--uid|-u)\s+(\d+)", dockerfile)
    assert m and m.group(1) == "10001"


def test_slots_serve_the_image_the_harness_tests(compose, monkeypatch):
    for slot in SLOTS:
        image = compose["services"][slot]["image"]
        monkeypatch.delenv("AGENT_IMAGE_TAG", raising=False)
        assert _interpolate(image, {}) == run_test.bundled_image_ref() == "creuset-agent:latest"
        monkeypatch.setenv("AGENT_IMAGE_TAG", "registry.local/agent:7")
        assert _interpolate(image, {"AGENT_IMAGE_TAG": "registry.local/agent:7"}) == run_test.bundled_image_ref()


def _healthcheck_exit_code(test: List[str], port: int, status: int) -> int:
    """Run a compose healthcheck command against a local server answering `status`."""

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(status)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        argv = [a.replace(f":{port}/", f":{server.server_port}/") for a in test[1:]]
        assert argv[0] == "python" and argv != test[1:], "expected a python check against the service's port"
        # A proxy from the developer's environment must not intercept 127.0.0.1;
        # in the container there is none.
        env = {k: v for k, v in os.environ.items() if not k.lower().endswith("_proxy")}
        return subprocess.run([sys.executable, *argv[1:]], capture_output=True, timeout=30, env=env).returncode
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("service, port", [("agent-blue", 8000), ("agent-green", 8000), ("mock-services", 8001)])
def test_healthchecks_need_no_curl_and_fail_on_503(compose, service, port):
    test = compose["services"][service]["healthcheck"]["test"]
    assert test[0] == "CMD" and "curl" not in " ".join(test)  # the images ship no curl
    assert _healthcheck_exit_code(test, port, 200) == 0
    # A slot that cannot write live traffic answers 503: that must be unhealthy.
    assert _healthcheck_exit_code(test, port, 503) != 0


def test_mock_services_strict_runs_is_passed_through_and_off_by_default(compose, monkeypatch):
    value = compose["services"]["mock-services"]["environment"]["MOCK_STRICT_RUNS"]
    assert value == "${MOCK_STRICT_RUNS:-0}"
    mock = sys.modules.get("mock_services_main") or load_module(
        "mock_services_main", ROOT / "sandbox" / "mock_services" / "main.py")
    monkeypatch.setenv("MOCK_STRICT_RUNS", _interpolate(value, {}))
    assert mock._env_flag("MOCK_STRICT_RUNS") is False  # the default starts, lenient


def test_router_upstream_timeout_is_passed_through(compose):
    env = compose["services"]["router"]["environment"]
    assert env["STATE_FILE"] == "/app/state/state.json"  # still wins over CREUSET_STATE_DIR
    assert env["ROUTER_UPSTREAM_TIMEOUT"] == "${ROUTER_UPSTREAM_TIMEOUT:-30}"
    rendered = {"ROUTER_UPSTREAM_TIMEOUT": _interpolate(env["ROUTER_UPSTREAM_TIMEOUT"], {})}
    assert router._upstream_timeout_from(rendered) == router._upstream_timeout_from({}) == 30.0


def test_service_container_and_network_names_are_unchanged(compose):
    # Existing checkouts find their running stack by these names, and
    # sandbox/run_test.py's defaults (creuset-net, mock-services, llm-proxy) assume them.
    names = {name: svc.get("container_name") for name, svc in compose["services"].items()}
    assert names == {"llm-proxy": "llm-proxy", "mock-services": "mock-services", "agent-blue": "agent-blue",
                     "agent-green": "agent-green", "router": "creuset-router"}
    networks = compose["networks"]
    assert networks["creuset-net"]["name"] == run_test.NETWORK == "creuset-net"
    assert networks["creuset-net"]["internal"] is True
    assert networks["creuset-edge"]["name"] == "creuset-edge"
    assert (run_test.MOCK_CONTAINER, run_test.PROXY_CONTAINER) == ("mock-services", "llm-proxy")
