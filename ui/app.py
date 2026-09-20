"""
ui/app.py
──────────
Local results browser for Creuset — a read-only view over everything the gate
has already written to logs/.

It is deliberately READ-ONLY. It starts no containers, calls no LLM, and spends
no provider quota, so it is safe to leave running and safe to demo repeatedly.
Docker does not need to be up. The one exception is /api/infra, which shells out
to `docker` to report whether a *live* run would be possible; the UI only calls
it when asked, because it is slow when Docker is down.

Run it:
    .venv/Scripts/python.exe -m uvicorn ui.app:app --port 8090
or just double-click Creuset.bat in the repo root.

What it reads:
    logs/runs/<batch>/manifest.json   batch manifests written by attacks/loader.py
    logs/runs/<batch>/<ID>.json       one transcript per case
    logs/**/*.json                    score reports (judge/score.py --output)
    logs/gate_runs/gate_*.json        gate audit records (score report nested)
    deploy/state/state.json           blue/green state
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

_ROOT = Path(__file__).resolve().parent.parent
_LOGS = _ROOT / "logs"
_RUNS = _LOGS / "runs"
_STATIC = Path(__file__).resolve().parent / "static"
_STATE_FILE = _ROOT / "deploy" / "state" / "state.json"

app = FastAPI(title="Creuset Results Browser", version="1.0.0")


# ── Safe path handling ────────────────────────────────────────────────────────

def _safe_log_path(rel: str) -> Path:
    """
    Resolve `rel` inside logs/ or refuse.

    The browser sends paths back to us, so they are untrusted input: without this
    a crafted `../../` would read anything on the disk. Anchored at logs/ because
    that is the only tree this app is allowed to read files out of.
    """
    base = _LOGS.resolve()
    try:
        target = (base / rel).resolve()
    except (OSError, ValueError):
        raise HTTPException(status_code=400, detail="Bad path.")
    if target != base and base not in target.parents:
        raise HTTPException(status_code=403, detail="Path is outside logs/.")
    if not target.is_file():
        raise HTTPException(status_code=404, detail=f"No such file: {rel}")
    return target


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise HTTPException(status_code=422, detail=f"Unreadable JSON: {type(e).__name__}")


def _rel(path: Path) -> str:
    return path.resolve().relative_to(_LOGS.resolve()).as_posix()


# ── Discovery ─────────────────────────────────────────────────────────────────

def _is_score_report(d: Any) -> bool:
    return isinstance(d, dict) and "gate_verdict" in d and "results" in d


def _severity_summary(report: Dict[str, Any]) -> Dict[str, Any]:
    out = {}
    for sev, d in (report.get("aggregation") or {}).items():
        if d.get("count"):
            out[sev] = {"passed": d["passed"], "count": d["count"],
                        "rate": d.get("rate"), "threshold": d.get("threshold"),
                        "met": d.get("met")}
    return out


def _invalid_reasons(report: Dict[str, Any]) -> List[str]:
    """Plain-English reasons a report is not a measurement. Empty = it is one."""
    reasons = []
    missing = (report.get("coverage") or {}).get("missing") or []
    unmeasured = report.get("unmeasured") or []
    ran_but_failed = [c for c in unmeasured if c not in missing]
    if missing:
        reasons.append(f"{len(missing)} case(s) produced no transcript at all: {', '.join(missing)}")
    if ran_but_failed:
        reasons.append(f"{len(ran_but_failed)} case(s) ran but did not complete "
                       f"(usually a provider 429): {', '.join(ran_but_failed)}")
    if report.get("judge_errors"):
        reasons.append(f"The judge could not be reached for {len(report['judge_errors'])} case(s): "
                       f"{', '.join(report['judge_errors'])}")
    if report.get("truncated_finalizer"):
        reasons.append(f"The empty-answer finalizer was truncated for "
                       f"{', '.join(report['truncated_finalizer'])} — those answers stop mid-sentence")
    if report.get("batch_complete") is False:
        reasons.append("The batch was stopped early by the quota circuit breaker")
    return reasons


def _report_card(path: Path, report: Dict[str, Any], source: str,
                 extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    models = report.get("models") or {}
    judge_model = models.get("judge")
    results = report.get("results") or []
    library = Path(str(report.get("library") or "")).name
    return {
        "path": _rel(path),
        "source": source,
        "name": path.stem,
        "ts": report.get("ts") or int(path.stat().st_mtime),
        "variant": report.get("variant"),
        "library": library or None,
        # Adversarial and benign runs use the same machinery but mean opposite
        # things: a FAIL on an attack case is a detection, a FAIL on a benign
        # task is a false positive. Labelling both "detected" would invert the
        # meaning of the benign numbers.
        "kind": "benign" if "benign" in library.lower() else "adversarial",
        "gate_verdict": report.get("gate_verdict"),
        # A report scored with --skip-model-judge has no judge model. That is the
        # difference between "the rules alone say this" and "both layers do",
        # which is the single most important thing to see at a glance here.
        "layer": "rule only" if not judge_model else "rule + judge",
        "agent_model": models.get("agent"),
        "judge_model": judge_model,
        "valid": report.get("valid"),
        "invalid_reasons": _invalid_reasons(report),
        "case_count": len(results),
        "detected": sum(1 for r in results if r.get("final") == "FAIL"),
        "severity": _severity_summary(report),
        **(extra or {}),
    }


def _discover_reports() -> List[Dict[str, Any]]:
    """Every score report under logs/, including ones nested in gate records."""
    cards: List[Dict[str, Any]] = []
    for path in sorted(_LOGS.rglob("*.json")):
        posix = path.as_posix()
        if "/runs/" in posix or "/live_traffic/" in posix:
            continue  # transcripts and batch manifests are handled separately
        data = None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue
        if _is_score_report(data):
            cards.append(_report_card(path, data, "score report"))
        elif isinstance(data, dict) and _is_score_report(data.get("score_report")):
            # gate/run_gate.py audit record: the report is nested, and the record
            # adds what the gate then DID about it.
            cards.append(_report_card(
                path, data["score_report"], "gate run",
                {"decision": data.get("decision"), "version": data.get("version"),
                 "datetime": data.get("datetime")},
            ))
    cards.sort(key=lambda c: c["ts"], reverse=True)
    return cards


def _discover_batches() -> List[Dict[str, Any]]:
    out = []
    if not _RUNS.is_dir():
        return out
    for manifest_path in sorted(_RUNS.glob("*/manifest.json")):
        try:
            m = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        cases = m.get("cases") or []
        models = sorted({c.get("agent_model") for c in cases if c.get("agent_model")})
        out.append({
            "batch": manifest_path.parent.name,
            "ts": m.get("ts") or int(manifest_path.stat().st_mtime),
            "variant": m.get("variant"),
            "library": Path(str(m.get("library") or "")).name or None,
            "case_count": m.get("case_count"),
            "present": len(cases),
            "completed": sum(1 for c in cases if c.get("status") == "completed"),
            "complete": m.get("complete"),
            "agent_models": models or ([m["agent_model"]] if m.get("agent_model") else []),
            "resumes": len(m.get("resumes") or []),
        })
    out.sort(key=lambda b: b["ts"], reverse=True)
    return out


def _deploy_state() -> Optional[Dict[str, Any]]:
    if not _STATE_FILE.is_file():
        return None
    try:
        return json.loads(_STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


# ── API ───────────────────────────────────────────────────────────────────────

@app.get("/api/overview")
def overview() -> Dict[str, Any]:
    return {
        "reports": _discover_reports(),
        "batches": _discover_batches(),
        "deploy": _deploy_state(),
        "root": str(_ROOT),
    }


@app.get("/api/report")
def report(path: str = Query(..., description="Path relative to logs/")) -> Dict[str, Any]:
    data = _read_json(_safe_log_path(path))
    rep = data.get("score_report") if isinstance(data, dict) and "score_report" in data else data
    if not _is_score_report(rep):
        raise HTTPException(status_code=422, detail="Not a score report.")
    return {
        "meta": _report_card(_safe_log_path(path), rep,
                             "gate run" if data is not rep else "score report"),
        "aggregation": rep.get("aggregation"),
        "by_category": rep.get("by_category"),
        "coverage": rep.get("coverage"),
        "judge_probes": rep.get("judge_probes"),
        "results": rep.get("results"),
        "gate": ({"decision": data.get("decision"), "version": data.get("version"),
                  "error": data.get("error")} if data is not rep else None),
    }


@app.get("/api/batch")
def batch(name: str = Query(..., description="Batch directory name under logs/runs/")) -> Dict[str, Any]:
    manifest_path = _safe_log_path(f"runs/{name}/manifest.json")
    m = _read_json(manifest_path)
    cases = []
    for entry in m.get("cases") or []:
        cases.append({
            "id": entry.get("id"),
            "status": entry.get("status"),
            "elapsed_seconds": entry.get("elapsed_seconds"),
            "agent_model": entry.get("agent_model"),
        })
    return {"batch": name, "manifest": m, "cases": cases}


@app.get("/api/transcript")
def transcript(batch: str = Query(...), case: str = Query(...)) -> Dict[str, Any]:
    path = _safe_log_path(f"runs/{batch}/{case}.json")
    t = _read_json(path)
    # Transcripts carry whole tool outputs and can be large; the browser only
    # needs enough to show what happened, so trim the long tails here rather
    # than shipping megabytes into a table cell.
    def clip(v: Any, n: int = 4000) -> str:
        s = v if isinstance(v, str) else json.dumps(v, default=str, indent=2)
        return s if len(s) <= n else s[:n] + f"\n… [+{len(s) - n} more characters]"

    return {
        "test_id": t.get("test_id"),
        "variant": t.get("variant"),
        "status": t.get("status"),
        "model": t.get("model"),
        "elapsed_seconds": t.get("elapsed_seconds"),
        "llm_calls_made": t.get("llm_calls_made"),
        "llm_calls_limit": t.get("llm_calls_limit"),
        "budget_ok": t.get("budget_ok"),
        "stopped_early": t.get("stopped_early"),
        "finalizer_used": t.get("finalizer_used"),
        "finalizer_truncated": t.get("finalizer_truncated"),
        "finalizer_error": t.get("finalizer_error"),
        "error": clip(t.get("error") or "", 2000) or None,
        "output": t.get("output") or "",
        "tool_calls": [{"tool": c.get("tool"), "input": clip(c.get("input"), 1200),
                        "output": clip(c.get("output"), 2500)}
                       for c in (t.get("tool_calls") or [])],
        "service_audit": t.get("service_audit"),
        "path": _rel(path),
    }


@app.get("/api/infra")
def infra() -> Dict[str, Any]:
    """
    Whether a LIVE run would be possible right now. Separate from everything else
    because it shells out to `docker`, which is slow to fail when Docker Desktop
    is not running — and this whole app is meant to work fine without it.
    """
    sys.path.insert(0, str(_ROOT / "sandbox"))
    try:
        from run_test import preflight  # noqa: WPS433 — imported lazily on purpose
        problems = preflight()
    except Exception as e:  # pylint: disable=broad-except
        return {"ready": False, "problems": [f"Could not run preflight: {type(e).__name__}: {e}"]}
    return {"ready": not problems, "problems": problems}


# ── Static UI ─────────────────────────────────────────────────────────────────

app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(str(_STATIC / "index.html"))
