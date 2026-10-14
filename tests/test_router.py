"""Blue/green router: never guess which slot is live, never relay hop-by-hop headers."""

import json
import sys

import httpx
import pytest
from fastapi.testclient import TestClient

import router
import switch
from conftest import ROOT, load_module


@pytest.fixture
def state(tmp_path, monkeypatch):
    path = tmp_path / "state.json"
    monkeypatch.setattr(router, "_STATE_FILE", path)
    return path


@pytest.fixture
def upstream(monkeypatch):
    """Capture what the router sends to the slot and answer with set headers."""
    seen = {}
    real_client = httpx.AsyncClient

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["headers"] = dict(request.headers)
        if "raise" in seen:
            raise seen["raise"]
        return httpx.Response(200, json={"ok": True},
                              headers={"Connection": "close", "Keep-Alive": "timeout=5",
                                       "X-Slot": "green"})

    def make_client(**kw):
        seen["client_kwargs"] = kw
        return real_client(transport=httpx.MockTransport(handler), **kw)

    monkeypatch.setattr(router.httpx, "AsyncClient", make_client)
    return seen


client = TestClient(router.app)


def test_missing_state_defaults_to_blue(state):
    assert client.get("/health").json()["active_slot"] == "blue"


@pytest.mark.parametrize("content", ['{"active": "gre', '["green"]', '{"active": "purple"}'])
def test_unusable_state_fails_closed(state, upstream, content):
    state.write_text(content)
    assert client.get("/health").status_code == 503
    assert client.post("/invoke", json={"input": "hi"}).status_code == 503
    assert "url" not in upstream  # nothing was forwarded anywhere


def test_proxies_to_active_slot_without_hop_by_hop_headers(state, upstream):
    state.write_text(json.dumps({"active": "green"}))
    resp = client.post("/invoke?x=1", json={"input": "hi"},
                       headers={"Connection": "keep-alive, X-Secret", "TE": "trailers"})
    assert resp.status_code == 200 and resp.json() == {"ok": True}
    assert upstream["url"] == "http://agent-green:8000/invoke?x=1"
    assert "te" not in upstream["headers"]
    assert resp.headers["x-slot"] == "green"
    assert "keep-alive" not in resp.headers


def test_oversized_body_rejected(state, upstream, monkeypatch):
    monkeypatch.setattr(router, "_MAX_BODY_BYTES", 10)
    resp = client.post("/invoke", content=b"x" * 100)
    assert resp.status_code == 413
    assert "url" not in upstream


# ── Configuration ────────────────────────────────────────────────────────────

def test_state_file_env_wins_over_state_dir(tmp_path):
    # Compose sets STATE_FILE to the container's read-only mount; nothing else
    # in the environment may redirect a running router away from it.
    env = {"STATE_FILE": "/app/state/state.json", "CREUSET_STATE_DIR": str(tmp_path)}
    assert router._state_file_from(env).as_posix() == "/app/state/state.json"


@pytest.mark.parametrize("state_file", [None, ""])
def test_state_dir_env_is_honoured_without_state_file(tmp_path, state_file):
    env = {"CREUSET_STATE_DIR": str(tmp_path)}
    if state_file is not None:
        env["STATE_FILE"] = state_file
    assert router._state_file_from(env) == tmp_path / "state.json"


def test_default_state_file_is_deploy_state():
    assert router._state_file_from({}) == ROOT / "deploy" / "state" / "state.json"


def test_router_and_switch_agree_on_a_relative_state_dir():
    """Otherwise switch.py would write one file while a host router read another."""
    env = {"CREUSET_STATE_DIR": "tmp/demo"}
    assert router._state_file_from(env) == switch._state_dir_from(env) / "state.json"


def test_env_is_read_at_import(tmp_path, monkeypatch):
    # STATE_FILE set but empty, so a developer's .env cannot fill it in.
    monkeypatch.setenv("STATE_FILE", "")
    monkeypatch.setenv("CREUSET_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("ROUTER_UPSTREAM_TIMEOUT", "12.5")
    try:
        fresh = load_module("router_env_probe", ROOT / "deploy" / "router.py")
    finally:
        sys.modules.pop("router_env_probe", None)
    assert fresh._STATE_FILE == tmp_path / "state.json"
    assert fresh._UPSTREAM_TIMEOUT == 12.5


@pytest.mark.parametrize("raw, expected", [(None, 30.0), ("", 30.0), ("90", 90.0), (" 0.5 ", 0.5)])
def test_upstream_timeout_parsing(raw, expected):
    env = {} if raw is None else {"ROUTER_UPSTREAM_TIMEOUT": raw}
    assert router._upstream_timeout_from(env) == expected


@pytest.mark.parametrize("raw", ["0", "-1", "abc", "nan", "inf", "30s"])
def test_unusable_upstream_timeout_refuses_to_start(raw):
    with pytest.raises(ValueError, match="ROUTER_UPSTREAM_TIMEOUT"):
        router._upstream_timeout_from({"ROUTER_UPSTREAM_TIMEOUT": raw})


def test_proxy_uses_the_configured_upstream_timeout(state, upstream, monkeypatch):
    monkeypatch.setattr(router, "_UPSTREAM_TIMEOUT", 120.0)
    assert client.post("/invoke", json={"input": "hi"}).status_code == 200
    assert upstream["client_kwargs"]["timeout"] == 120.0


def test_upstream_timeout_is_a_502_not_a_traceback(state, upstream):
    upstream["raise"] = httpx.ReadTimeout("slow slot")
    resp = client.post("/invoke", json={"input": "hi"})
    assert resp.status_code == 502
    assert "ReadTimeout" in resp.json()["error"]
