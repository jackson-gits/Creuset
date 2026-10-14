"""Blue/green router: never guess which slot is live, never relay hop-by-hop headers."""

import json

import httpx
import pytest
from fastapi.testclient import TestClient

import router


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
        return httpx.Response(200, json={"ok": True},
                              headers={"Connection": "close", "Keep-Alive": "timeout=5",
                                       "X-Slot": "green"})

    monkeypatch.setattr(router.httpx, "AsyncClient",
                        lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw))
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
