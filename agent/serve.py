"""
agent/serve.py
──────────────
Long-running service mode for the blue/green deployment slots.

    uvicorn serve:app --host 0.0.0.0 --port 8000

Endpoints (reached only through the router — slots sit on the internal
sandbox network and publish no ports):
    GET  /health  → {"status": "ok", "slot", "variant", "version",
                     "live_traffic_writable": true}
                    503 with "live_traffic_writable": false (and
                    "live_traffic_error") when transcripts cannot be written
    POST /invoke  {"input": "..."} → {"request_id", "output", "status", ...}

Every request runs in its own isolated mock-services world and its full
transcript is written to LIVE_TRAFFIC_DIR (bind-mounted to
logs/live_traffic/), which is what monitor/watch.py watches.

A slot that cannot write there still answers requests, but it cannot be
monitored: the monitor would watch an empty directory and never roll back. So
/health reports it as unhealthy, which makes `docker compose up --wait` (and
the gate's staging step) fail instead of deploying it, and the first failure
is logged to stderr. The usual cause is native Linux, where the bind mount
keeps the host directory's owner and the slot's uid (CREUSET_UID, default
10001) cannot write to it.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator, Dict, Optional

from fastapi import FastAPI, Response
from pydantic import BaseModel, Field

from run_agent import _load_variant, run_scenario

_VARIANT = os.getenv("AGENT_VARIANT", "hardened")
_VERSION = os.getenv("AGENT_VERSION", "unknown")
_SLOT = os.getenv("SLOT", "unknown")
_LIVE_DIR = Path(os.getenv("LIVE_TRAFFIC_DIR", "/app/live_traffic"))
_MAX_ACTIONS = int(os.getenv("LIVE_MAX_ACTIONS", "8"))

# Refuse to start on a variant that cannot load. Otherwise the slot comes up
# healthy and then fails every request — and the gate's `--wait` on the
# healthcheck would wave it through to receive live traffic.
_load_variant(_VARIANT)


# ── Live-traffic writability ──────────────────────────────────────────────────
# None = transcripts can be written; otherwise why not. Probed once at startup
# and, while it is failing, again on every /health — so a directory fixed in
# place (chown, remount) brings the slot back without a restart, while a
# healthy slot's healthcheck touches no disk. Request threads and the
# healthcheck share it, hence the lock.

_live_lock = threading.Lock()
_live_probed = False
_live_error: Optional[str] = None

_LINUX_HINT = ("On native Linux the bind mount keeps the host directory's owner: run the slots as "
               "that user (set CREUSET_UID and CREUSET_GID to the output of `id -u` and `id -g`, in "
               ".env or the environment, then recreate the slots), or chown logs/live_traffic to the "
               "slot's uid (default 10001).")


def _describe(e: OSError) -> str:
    return f"{type(e).__name__}: {e}"


def _probe_file() -> Path:
    # A dotfile that is not *.json: the monitor globs *.json, so a probe that
    # outlives a crash is never read as traffic. Per slot, because both slots
    # share the directory.
    return _LIVE_DIR / f".{_SLOT}.write-probe"


def _probe() -> Optional[str]:
    """None when LIVE_TRAFFIC_DIR accepts a new file, else why it does not."""
    probe = _probe_file()
    try:
        _LIVE_DIR.mkdir(parents=True, exist_ok=True)
        probe.write_bytes(b"")
    except OSError as e:
        return _describe(e)
    try:
        probe.unlink()
    except OSError:
        pass  # the write worked, which is all a transcript needs
    return None


def _record(error: Optional[str]) -> None:
    """Store the latest outcome; log only a change, so a failing slot does not flood stderr."""
    global _live_error, _live_probed
    with _live_lock:
        was_failing = _live_error is not None
        _live_probed = True
        _live_error = error
    if error is not None and not was_failing:
        print(f"[creuset serve:{_SLOT}] cannot write live-traffic transcripts to {_LIVE_DIR} ({error}). "
              f"The monitor will see no traffic from this slot, and /health returns 503 until this is "
              f"fixed. {_LINUX_HINT}", file=sys.stderr, flush=True)
    elif error is None and was_failing:
        print(f"[creuset serve:{_SLOT}] live-traffic transcripts are writable again in {_LIVE_DIR}.",
              file=sys.stderr, flush=True)


def _live_traffic_error() -> Optional[str]:
    """The current writability problem, re-probing only before the first probe or while failing."""
    with _live_lock:
        settled = _live_probed and _live_error is None
    if not settled:
        _record(_probe())
    return _live_error


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    _record(_probe())  # at startup, so the first healthcheck already knows
    yield


app = FastAPI(title=f"Creuset agent ({_SLOT})", version="2.0.0", lifespan=_lifespan)


class InvokeRequest(BaseModel):
    input: str = Field(..., min_length=1, max_length=8000)


@app.get("/health")
def health(response: Response) -> Dict[str, Any]:
    error = _live_traffic_error()
    body: Dict[str, Any] = {
        "status": "ok" if error is None else "unhealthy",
        "slot": _SLOT,
        "variant": _VARIANT,
        "version": _VERSION,
        "live_traffic_writable": error is None,
    }
    if error is not None:
        body["live_traffic_error"] = error
        response.status_code = 503
    return body


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
    except OSError as e:
        # Monitoring must never take the service down, so the request is still
        # answered — but silently passing here is what let a Linux slot run
        # unmonitored. /health now reports it and the first failure is logged.
        _record(_describe(e))
    else:
        _record(None)

    return {
        "request_id": request_id,
        "slot": _SLOT,
        "version": _VERSION,
        "status": transcript["status"],
        "output": transcript["output"],
    }
