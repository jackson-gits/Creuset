"""
judge/waivers.py
─────────────────
Accepted risk, written down: a waiver lets a known failure stop blocking the
gate until a date, for a stated reason.

A team that points the gate at an existing agent usually finds failures it
cannot fix today. Without waivers its choices are a gate that blocks every
deploy, or no gate. With them, each known failure is named, explained, owned
and time-limited, and everything else still blocks:

    waivers:
      - case: PI-005
        reason: Discloses customer names and spend; prompt fix tracked in SEC-142.
        expires: 2026-12-31
        approved_by: security@yourco.example

What a waiver does and does not do:

  • It applies only to a case that FAILed on the agent's behaviour. A case that
    did not complete (timeout, quota, a crash) or whose judge was unreachable
    stays a FAIL: a waiver accepts a known behaviour, not a missing measurement,
    and such a report is not `valid` anyway.
  • The case keeps `final: FAIL` and gains `waived`; only the thresholds count
    it as passing. Nothing is hidden in the report.
  • An expired waiver is ignored (the case blocks again) and listed, so expiry
    is visible rather than silent. A waiver whose case passed is listed as
    unused: the risk it accepted is gone, so it should be deleted.
  • A malformed file is an error, never "no waivers": a typo must not turn a
    known failure back into a surprise, nor a missing date into a forever.
"""

from __future__ import annotations

import datetime as dt
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

_FIELDS = {"case", "reason", "expires", "approved_by"}
_CASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def load_waivers(path: Path) -> List[Dict[str, Any]]:
    """The waivers in `path`, validated. Raises ValueError naming every problem."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as e:
        raise ValueError(f"cannot read waivers {path}: {e}") from e
    entries = raw.get("waivers") if isinstance(raw, dict) else None
    if not isinstance(entries, list):
        raise ValueError(f"{path}: expected a `waivers:` list")
    problems: List[str] = []
    seen: Dict[str, int] = {}
    waivers: List[Dict[str, Any]] = []
    for number, entry in enumerate(entries, 1):
        where = f"{path} waiver #{number}"
        if not isinstance(entry, dict):
            problems.append(f"{where}: expected a mapping")
            continue
        unknown = sorted(set(entry) - _FIELDS)
        if unknown:
            problems.append(f"{where}: unknown field(s) {unknown}")
        case = entry.get("case")
        if not isinstance(case, str) or not _CASE_ID.fullmatch(case):
            problems.append(f"{where}: `case` must be a case id")
            continue
        if case in seen:
            problems.append(f"{where}: {case} is already waived by waiver #{seen[case]}")
        seen[case] = number
        reason = entry.get("reason")
        if not isinstance(reason, str) or len(reason.strip()) < 10:
            problems.append(f"{where}: `reason` must say why (at least 10 characters)")
        expires = entry.get("expires")
        if isinstance(expires, str):
            try:
                expires = dt.date.fromisoformat(expires)
            except ValueError:
                expires = None
        if not isinstance(expires, dt.date) or isinstance(expires, dt.datetime):
            problems.append(f"{where}: `expires` must be a date (YYYY-MM-DD); a waiver never lasts forever")
            continue
        approved_by = entry.get("approved_by")
        if approved_by is not None and not isinstance(approved_by, str):
            problems.append(f"{where}: `approved_by` must be text")
        waivers.append({"case": case, "reason": str(reason).strip(), "expires": expires.isoformat(),
                        **({"approved_by": approved_by} if approved_by else {})})
    if problems:
        raise ValueError("; ".join(problems))
    return waivers


def _measured(result: Dict[str, Any]) -> bool:
    return result.get("status") == "completed" and not result.get("judge_error") \
        and not result.get("finalizer_truncated")


def apply_waivers(results: List[Dict[str, Any]], waivers: List[Dict[str, Any]],
                  today: Optional[dt.date] = None, source: Optional[str] = None) -> Dict[str, Any]:
    """
    Mark waived failures in `results` (adds `waived`) and return the summary
    the report carries: which waivers applied, expired, or went unused.
    """
    today = today or dt.date.today()
    by_case = {r["test_id"]: r for r in results}
    summary: Dict[str, Any] = {"file": source, "applied": [], "expired": [], "unused": [],
                               "not_applicable": []}
    for waiver in waivers:
        result = by_case.get(waiver["case"])
        if dt.date.fromisoformat(waiver["expires"]) < today:
            summary["expired"].append(waiver["case"])
        elif result is None or result["final"] == "PASS":
            summary["unused"].append(waiver["case"])
        elif not _measured(result):
            # Accepting a behaviour needs the behaviour to have been measured.
            summary["not_applicable"].append(waiver["case"])
        else:
            result["waived"] = waiver
            summary["applied"].append(waiver["case"])
    return summary


def counts_as_pass(result: Dict[str, Any]) -> bool:
    """For the thresholds: a PASS, or a measured FAIL someone accepted, in writing, until a date."""
    return result.get("final") == "PASS" or bool(result.get("waived"))
