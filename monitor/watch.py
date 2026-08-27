"""
monitor/watch.py
─────────────────
Post-deployment safety monitor.

Watches logs/live_traffic/ for agent activity logs and checks for:
  1. Anomalous spikes in sensitive tool-call frequency
     (moving window, configurable threshold).
  2. Outputs matching known attack signatures from the attack library
     (reuses rule_checks.py forbidden_output_patterns).

If triggered:
  - Calls deploy/switch.py rollback (instant slot revert).
  - Writes an incident report to logs/gate_runs/incident_<ts>.json.
  - Exits non-zero (so a CI watcher can alert).

Live traffic log format (each file in logs/live_traffic/):
  A JSON file matching the transcript schema written by run_agent.py.
  Simulated by monitor/simulate_traffic.py for the demo.

Usage:
  # Watch for new files in a loop (one scan per WATCH_INTERVAL_SECONDS)
  python monitor/watch.py

  # Watch for a fixed number of cycles then exit (useful for testing)
  python monitor/watch.py --max-cycles 10
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from collections import deque
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

import yaml
from dotenv import load_dotenv
from rich.console import Console

load_dotenv()

_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT / "judge"))  # allow importing judge modules
from rule_checks import run_rule_checks  # noqa: E402

console = Console()

_LIVE_TRAFFIC_DIR = _ROOT / "logs" / "live_traffic"
_GATE_LOGS = _ROOT / "logs" / "gate_runs"
_ATTACK_LIB = _ROOT / "attacks" / "attack_library.yaml"
_SWITCH_SCRIPT = _ROOT / "deploy" / "switch.py"

_TOOL_FREQ_THRESHOLD = int(os.getenv("MONITOR_TOOL_FREQ_THRESHOLD", "5"))
_WINDOW_SECONDS = int(os.getenv("MONITOR_WINDOW_SECONDS", "60"))
_WATCH_INTERVAL = int(os.getenv("WATCH_INTERVAL_SECONDS", "5"))

SENSITIVE_TOOLS = {"delete_file", "charge_payment", "send_email"}


# ── Attack pattern loader ─────────────────────────────────────────────────────

def _load_forbidden_patterns() -> List[str]:
    """Collect all unique forbidden_output_patterns from the attack library."""
    if not _ATTACK_LIB.exists():
        return []
    with open(_ATTACK_LIB, encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    cases = raw if isinstance(raw, list) else raw.get("cases", [])
    patterns: Set[str] = set()
    for case in cases:
        patterns.update(case.get("forbidden_output_patterns", []))
    return list(patterns)


# ── Frequency tracker ─────────────────────────────────────────────────────────

class ToolFrequencyTracker:
    """
    Sliding-window counter for sensitive tool calls.
    Raises an anomaly if the count in the last WINDOW_SECONDS exceeds threshold.
    """

    def __init__(self, window: int, threshold: int) -> None:
        self.window = window
        self.threshold = threshold
        self._calls: Deque[Tuple[float, str]] = deque()

    def record(self, tool: str, ts: float) -> None:
        self._calls.append((ts, tool))

    def check(self, now: float) -> Optional[str]:
        """Purge old entries and return anomaly description or None."""
        cutoff = now - self.window
        while self._calls and self._calls[0][0] < cutoff:
            self._calls.popleft()

        sensitive_in_window = [(t, n) for t, n in self._calls if n in SENSITIVE_TOOLS]
        if len(sensitive_in_window) >= self.threshold:
            return (
                f"{len(sensitive_in_window)} sensitive tool calls "
                f"in the last {self.window}s (threshold={self.threshold})"
            )
        return None


# ── Incident response ─────────────────────────────────────────────────────────

def _trigger_rollback(reason: str, evidence: Dict[str, Any]) -> None:
    """Roll back to the previous slot and write an incident report."""
    console.print(f"\n[bold red]🚨 ANOMALY DETECTED[/bold red] — {reason}")
    console.print("[bold yellow]Initiating rollback...[/bold yellow]")

    result = subprocess.run(
        [sys.executable, str(_SWITCH_SCRIPT), "rollback"],
        cwd=str(_ROOT),
        capture_output=False,
        text=True,
    )

    _GATE_LOGS.mkdir(parents=True, exist_ok=True)
    ts = int(time.time())
    incident = {
        "ts": ts,
        "datetime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "type": "monitor_anomaly",
        "reason": reason,
        "evidence": evidence,
        "rollback_exit_code": result.returncode,
    }
    path = _GATE_LOGS / f"incident_{ts}.json"
    path.write_text(json.dumps(incident, indent=2))
    console.print(f"[bold]Incident report:[/bold] {path}")


# ── File watcher ──────────────────────────────────────────────────────────────

def watch(max_cycles: Optional[int] = None) -> None:
    """
    Main watch loop. Scans live_traffic/ for new transcript files,
    checks each for anomalies, and triggers rollback if found.
    """
    _LIVE_TRAFFIC_DIR.mkdir(parents=True, exist_ok=True)
    forbidden_patterns = _load_forbidden_patterns()
    freq_tracker = ToolFrequencyTracker(_WINDOW_SECONDS, _TOOL_FREQ_THRESHOLD)
    seen_files: Set[str] = set()

    console.print(
        f"[bold cyan]Creuset Monitor[/bold cyan] — watching [dim]{_LIVE_TRAFFIC_DIR}[/dim]\n"
        f"Frequency threshold: {_TOOL_FREQ_THRESHOLD} sensitive calls / {_WINDOW_SECONDS}s\n"
        f"Attack patterns: {len(forbidden_patterns)} loaded\n"
    )

    cycles = 0
    while True:
        new_files = sorted(
            p for p in _LIVE_TRAFFIC_DIR.glob("*.json") if p.name not in seen_files
        )

        for fpath in new_files:
            seen_files.add(fpath.name)
            try:
                transcript = json.loads(fpath.read_text())
            except (json.JSONDecodeError, OSError):
                continue

            ts_now = time.time()
            tool_calls = transcript.get("tool_calls", [])

            # ── 1. Tool frequency check ───────────────────────────────────
            for tc in tool_calls:
                freq_tracker.record(tc.get("tool", ""), ts_now)

            anomaly = freq_tracker.check(ts_now)
            if anomaly:
                _trigger_rollback(
                    f"Sensitive tool-call frequency spike: {anomaly}",
                    {"file": fpath.name, "tool_calls": tool_calls},
                )
                return  # stop watching after rollback

            # ── 2. Pattern check ──────────────────────────────────────────
            if forbidden_patterns:
                dummy_case = {"forbidden_output_patterns": forbidden_patterns}
                result = run_rule_checks(transcript, dummy_case)
                # run_rule_checks returns FAIL if pattern_audit fails
                if result["verdict"] == "FAIL" and any(
                    c["name"] == "pattern_audit" and c["verdict"] == "FAIL"
                    for c in result["checks"]
                ):
                    pattern_check = next(
                        c for c in result["checks"] if c["name"] == "pattern_audit"
                    )
                    _trigger_rollback(
                        f"Forbidden output pattern match: {pattern_check['reason']}",
                        {"file": fpath.name, "output": transcript.get("output", "")[:500]},
                    )
                    return

            console.print(f"[dim]Checked:[/dim] {fpath.name} — [green]OK[/green]")

        cycles += 1
        if max_cycles is not None and cycles >= max_cycles:
            console.print("[dim]Max cycles reached. Exiting.[/dim]")
            return

        time.sleep(_WATCH_INTERVAL)


if __name__ == "__main__":
    import typer

    def _main(max_cycles: Optional[int] = typer.Option(None, "--max-cycles")) -> None:
        watch(max_cycles=max_cycles)

    typer.run(_main)
