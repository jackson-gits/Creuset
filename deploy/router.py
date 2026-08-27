"""
deploy/router.py
─────────────────
Python FastAPI reverse-proxy — the non-optional default blue-green traffic router.

Reads deploy/state.json on every request to determine the active slot.
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

_STATE_FILE = Path(__file__).parent / "state.json"

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


def _active_upstream() -> str:
    """Read state.json and return the upstream URL for the active slot."""
    try:
        state = json.loads(_STATE_FILE.read_text())
        slot = state.get("active", "blue")
    except (FileNotFoundError, json.JSONDecodeError):
        slot = "blue"

    host, port = _SLOTS.get(slot, _SLOTS["blue"])
    return f"http://{host}:{port}"


@app.get("/health")
async def health() -> dict:
    active = json.loads(_STATE_FILE.read_text()).get("active", "blue") if _STATE_FILE.exists() else "blue"
    return {"status": "ok", "active_slot": active}


@app.get("/router/state")
async def router_state() -> dict:
    if _STATE_FILE.exists():
        return json.loads(_STATE_FILE.read_text())
    return {"active": "blue", "note": "state.json not found, defaulting to blue"}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def proxy(request: Request, path: str) -> Response:
    """Forward all requests to the active slot."""
    upstream = _active_upstream()
    target_url = f"{upstream}/{path}"

    # Rebuild query string
    qs = request.url.query
    if qs:
        target_url += f"?{qs}"

    body = await request.body()

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            resp = await client.request(
                method=request.method,
                url=target_url,
                headers={k: v for k, v in request.headers.items() if k.lower() != "host"},
                content=body,
            )
            return Response(
                content=resp.content,
                status_code=resp.status_code,
                headers=dict(resp.headers),
            )
        except httpx.ConnectError:
            return JSONResponse(
                status_code=503,
                content={"error": f"Cannot reach active slot: {upstream}", "active_slot": upstream},
            )


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("ROUTER_PORT", "8080"))
    uvicorn.run("router:app", host="0.0.0.0", port=port, reload=False)
