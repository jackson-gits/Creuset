"""
deploy/router.py
─────────────────
Python FastAPI reverse-proxy — the non-optional default blue-green traffic router.

Reads deploy/state/state.json (STATE_FILE) on every request to determine the
active slot.
Forwards all traffic to http://agent-{active}:8000.

Port: 8080 (external-facing)
Slots:
  blue  → http://agent-blue:8000  (or AGENT_BLUE_HOST:AGENT_BLUE_PORT)
  green → http://agent-green:8000 (or AGENT_GREEN_HOST:AGENT_GREEN_PORT)

Why Python instead of Nginx (Fix #3 from reviewer):
  Nginx as a default requires reloading config files on every switch,
  which adds operational complexity. This 40-line proxy reads state.json
  on every request — zero config reload needed. Nginx is documented as an
  upgrade path in deploy/README.md for high-traffic production use.

Design note (from reviewer):
  state.json is single-writer. This is safe for a single-demo POC with
  sequential gate runs. Not safe for concurrent gate runs; documented
  limitation in README.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

load_dotenv()

app = FastAPI(title="Creuset Router", version="1.0.0")

# In the container this is /app/state/state.json (deploy/state bind-mounted
# read-only); on the host it is deploy/state/state.json — the same file
# deploy/switch.py writes. It is re-read on every request: no reload on switch.
_STATE_FILE = Path(os.getenv("STATE_FILE") or (Path(__file__).parent / "state" / "state.json"))

_SLOTS = {
    "blue": (
        os.getenv("AGENT_BLUE_HOST", "agent-blue"),
        int(os.getenv("AGENT_BLUE_PORT", "8000")),
    ),
    "green": (
        os.getenv("AGENT_GREEN_HOST", "agent-green"),
        int(os.getenv("AGENT_GREEN_PORT", "8000")),
    ),
}


# Connection-level headers belong to one hop and must not be relayed (RFC 9110
# §7.6.1). Content-Length/-Encoding are recomputed: httpx hands back a decoded
# body, so echoing the upstream's values would describe bytes we never send.
_HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
               "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length"}
_STRIP_FROM_RESPONSE = _HOP_BY_HOP | {"content-encoding"}
_MAX_BODY_BYTES = int(os.getenv("ROUTER_MAX_BODY_BYTES", str(1024 * 1024)))


class StateError(Exception):
    """state.json exists but cannot say which slot is live."""


def _read_state() -> dict:
    """
    The router's view of deploy/state/state.json.

    A MISSING file means nothing has been deployed yet, and blue is the
    documented default. A file that exists but cannot be parsed, or names a
    slot that does not exist, is different: guessing "blue" there could send
    live traffic to the very build a rollback just moved away from. That is
    refused instead (fail closed).
    """
    try:
        raw = _STATE_FILE.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {"active": "blue", "note": "state.json not found, defaulting to blue"}
    except OSError as e:
        raise StateError(f"state.json unreadable: {type(e).__name__}") from e
    try:
        state = json.loads(raw)
    except json.JSONDecodeError as e:
        raise StateError("state.json is not valid JSON") from e
    if not isinstance(state, dict) or state.get("active", "blue") not in _SLOTS:
        raise StateError("state.json names no known active slot")
    state.setdefault("active", "blue")
    return state


def _active_upstream() -> str:
    """Return the upstream URL for the active slot (raises StateError)."""
    host, port = _SLOTS[_read_state()["active"]]
    return f"http://{host}:{port}"


def _state_unavailable(e: StateError) -> JSONResponse:
    return JSONResponse(status_code=503, content={"error": f"No traffic routed: {e}."})


@app.get("/health")
async def health() -> Response:
    try:
        return JSONResponse({"status": "ok", "active_slot": _read_state()["active"]})
    except StateError as e:
        return _state_unavailable(e)


@app.get("/router/state")
async def router_state() -> Response:
    try:
        return JSONResponse(_read_state())
    except StateError as e:
        return _state_unavailable(e)


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def proxy(request: Request, path: str) -> Response:
    """Forward all requests to the active slot."""
    try:
        upstream = _active_upstream()
    except StateError as e:
        return _state_unavailable(e)
    target_url = f"{upstream}/{path}"

    # Rebuild query string
    qs = request.url.query
    if qs:
        target_url += f"?{qs}"

    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > _MAX_BODY_BYTES:
        return JSONResponse(status_code=413, content={"error": "Request body too large."})
    body = await request.body()
    if len(body) > _MAX_BODY_BYTES:
        return JSONResponse(status_code=413, content={"error": "Request body too large."})

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            resp = await client.request(
                method=request.method,
                url=target_url,
                headers={k: v for k, v in request.headers.items() if k.lower() not in _HOP_BY_HOP},
                content=body,
            )
        except httpx.ConnectError:
            return JSONResponse(
                status_code=503,
                content={"error": f"Cannot reach active slot: {upstream}", "active_slot": upstream},
            )
        except httpx.HTTPError as e:
            return JSONResponse(
                status_code=502,
                content={"error": f"Active slot failed: {type(e).__name__}", "active_slot": upstream},
            )
    return Response(
        content=resp.content,
        status_code=resp.status_code,
        headers={k: v for k, v in resp.headers.items() if k.lower() not in _STRIP_FROM_RESPONSE},
    )


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("ROUTER_PORT", "8080"))
    uvicorn.run("router:app", host="0.0.0.0", port=port, reload=False)
