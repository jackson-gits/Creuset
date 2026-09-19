"""
agent/serve.py
──────────────
Long-running service mode for the blue/green deployment slots.

    uvicorn serve:app --host 0.0.0.0 --port 8000

Endpoints (reached only through the router — slots sit on the internal
sandbox network and publish no ports):
    GET  /health  → {"status": "ok", "slot", "variant", "version"}
    POST /invoke  {"input": "..."} → {"request_id", "output", "status", ...}

Every request runs in its own isolated mock-services world and its full
transcript is written to LIVE_TRAFFIC_DIR (bind-mounted to
logs/live_traffic/), which is what monitor/watch.py watches.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI
from pydantic import BaseModel, Field

from run_agent import run_scenario

_VARIANT = os.getenv("AGENT_VARIANT", "hardened")
_VERSION = os.getenv("AGENT_VERSION", "unknown")
_SLOT = os.getenv("SLOT", "unknown")
_LIVE_DIR = Path(os.getenv("LIVE_TRAFFIC_DIR", "/app/live_traffic"))
_MAX_ACTIONS = int(os.getenv("LIVE_MAX_ACTIONS", "8"))

app = FastAPI(title=f"Creuset agent ({_SLOT})", version="2.0.0")


class InvokeRequest(BaseModel):
    input: str = Field(..., min_length=1, max_length=8000)


@app.get("/health")
def health() -> Dict[str, Any]:
    return {"status": "ok", "slot": _SLOT, "variant": _VARIANT, "version": _VERSION}


@app.post("/invoke")
def invoke(req: InvokeRequest) -> Dict[str, Any]:
    request_id = uuid.uuid4().hex[:12]
    transcript = run_scenario(
        {"test_id": f"LIVE-{request_id}", "input_payload": req.input, "max_actions": _MAX_ACTIONS},
        _VARIANT,
        run_id=f"live-{_SLOT}-{request_id}",
    )
    transcript.update({
        "slot": _SLOT,
        "version": _VERSION,
        "input": req.input,
        "received_at": time.time(),
    })

    try:
        _LIVE_DIR.mkdir(parents=True, exist_ok=True)
        path = _LIVE_DIR / f"{_SLOT}_{int(time.time() * 1000)}_{request_id}.json"
        path.write_text(json.dumps(transcript, indent=2), encoding="utf-8")
    except OSError:
        pass  # monitoring must never take the service down

    return {
        "request_id": request_id,
        "slot": _SLOT,
        "version": _VERSION,
        "status": transcript["status"],
        "output": transcript["output"],
    }
