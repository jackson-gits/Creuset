"""
gate/run_gate.py
─────────────────
End-to-end deployment gate orchestrator.

Flow:
  1. Receive --version tag for the candidate agent build.
  2. Run the full attack library against the candidate (green slot) via the sandbox.
  3. Score all transcripts with the judge pipeline.
  4. If score clears all thresholds → call deploy/switch.py to flip blue→green.
  5. If score fails → block deployment, green stays down, blue stays live.
  6. Fail-closed: sandbox crash, timeout, or unexpected error = gate FAIL.

Every gate run writes a timestamped record to logs/gate_runs/:
  - Version tested
  - Full per-test results
  - Final verdict
  - Decision taken (deployed / blocked)

This is both the security audit trail and the evaluation dataset.

Usage:
  python gate/run_gate.py --version v1.2.3
  python gate/run_gate.py --version naive --variant naive
  python gate/run_gate.py --version hardened --variant hardened --skip-model-judge
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import typer
import yaml
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule

load_dotenv()

app = typer.Typer(add_completion=False)
console = Console()

_ROOT = Path(__file__).parent.parent
_ATTACK_LIB = _ROOT / "attacks" / "attack_library.yaml"
_GATE_LOGS = _ROOT / "logs" / "gate_runs"
_SCORE_SCRIPT = _ROOT / "judge" / "score.py"
_LOADER_SCRIPT = _ROOT / "attacks" / "loader.py"
_SWITCH_SCRIPT = _ROOT / "deploy" / "switch.py"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _run_attack_suite(variant: str) -> Optional[Path]:
    """
    Run the full attack library through the sandbox (calls loader.py).
    Returns the path to the batch manifest, or None on failure.
    """
    console.print(Rule("Phase 1 — Running attack suite"))
    cmd = [
        sys.executable, str(_LOADER_SCRIPT),
        "--variant", variant,
    ]
    console.print(f"[dim]{' '.join(cmd)}[/dim]")

    result = subprocess.run(cmd, cwd=str(_ROOT), capture_output=False, text=True)

    if result.returncode != 0:
        console.print("[red]✗ Attack suite runner failed (non-zero exit).[/red]")
        return None

    # Find the most recently written batch manifest
    logs_dir = _ROOT / "logs"
    manifests = sorted(logs_dir.glob("batch_*.json"), key=lambda p: p.stat().st_mtime)
    if not manifests:
        console.print("[red]✗ No batch manifest found after loader run.[/red]")
        return None

    return manifests[-1]


def _run_scorer(manifest: Path, skip_model_judge: bool) -> Optional[Dict[str, Any]]:
    """
    Run the judge/scorer on the batch manifest.
    Returns the parsed score report dict, or None on failure.
    """
    console.print(Rule("Phase 2 — Scoring transcripts"))

    ts = int(time.time())
    report_path = _GATE_LOGS / f"score_{ts}.json"
    _GATE_LOGS.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable, str(_SCORE_SCRIPT),
        "--manifest", str(manifest),
        "--output", str(report_path),
    ]
    if skip_model_judge:
        cmd.append("--skip-model-judge")

    console.print(f"[dim]{' '.join(cmd)}[/dim]")

    result = subprocess.run(cmd, cwd=str(_ROOT / "judge"), capture_output=False, text=True)

    if not report_path.exists():
        console.print("[red]✗ Score report not written. Treating as gate FAIL.[/red]")
        return None

    return json.loads(report_path.read_text())


def _write_gate_record(
    version: str,
    variant: str,
    score_report: Optional[Dict[str, Any]],
    verdict: str,
    decision: str,
    error: Optional[str] = None,
) -> Path:
    """Write the gate run audit record to logs/gate_runs/."""
    _GATE_LOGS.mkdir(parents=True, exist_ok=True)
    ts = int(time.time())
    record = {
        "ts": ts,
        "datetime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "version": version,
        "variant": variant,
        "verdict": verdict,
        "decision": decision,
        "error": error,
        "score_report": score_report,
    }
    path = _GATE_LOGS / f"gate_{ts}.json"
    path.write_text(json.dumps(record, indent=2))
    return path


def _do_switch(version: str) -> bool:
    """Call deploy/switch.py to flip traffic to green. Returns True on success."""
    cmd = [sys.executable, str(_SWITCH_SCRIPT), "switch", "green", "--version", version]
    result = subprocess.run(cmd, cwd=str(_ROOT), capture_output=False, text=True)
    return result.returncode == 0


# ── CLI ───────────────────────────────────────────────────────────────────────

@app.command()
def main(
    version: str = typer.Option(..., "--version", help="Version tag for the candidate agent (e.g. v1.2.3 or 'naive')."),
    variant: Optional[str] = typer.Option(None, "--variant", help="Agent variant override. Defaults to --version."),
    skip_model_judge: bool = typer.Option(False, "--skip-model-judge", help="Only run rule-based checks (faster, no LLM cost)."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Score but don't actually switch slots."),
) -> None:
    """
    Run the full Creuset deployment gate.

    Tests the candidate agent version, scores results, and flips the
    blue-green router only if all safety thresholds are met.
    """
    _variant = variant or version
    start_ts = time.time()

    console.print(
        Panel(
            f"[bold]Version:[/bold] {version}  [bold]Variant:[/bold] {_variant}  "
            f"[bold]Dry run:[/bold] {dry_run}",
            title="[bold cyan]Creuset Deployment Gate[/bold cyan]",
        )
    )

    # ── Step 1: Run attack suite ──────────────────────────────────────────────
    manifest = _run_attack_suite(_variant)

    if manifest is None:
        # Fail-closed: sandbox runner failure = gate FAIL
        record = _write_gate_record(
            version, _variant, None, "FAIL", "BLOCKED",
            error="Attack suite runner failed or produced no manifest.",
        )
        console.print(f"\n[bold red]⛔ GATE BLOCKED[/bold red] — sandbox failure. Audit: {record}")
        raise typer.Exit(code=1)

    console.print(f"[green]✓ Batch manifest:[/green] {manifest}")

    # ── Step 2: Score ─────────────────────────────────────────────────────────
    score_report = _run_scorer(manifest, skip_model_judge)

    if score_report is None:
        record = _write_gate_record(
            version, _variant, None, "FAIL", "BLOCKED",
            error="Scorer failed or produced no report.",
        )
        console.print(f"\n[bold red]⛔ GATE BLOCKED[/bold red] — scorer failure. Audit: {record}")
        raise typer.Exit(code=1)

    gate_verdict = score_report.get("gate_verdict", "FAIL")
    elapsed = round(time.time() - start_ts, 1)

    console.print(Rule("Gate Decision"))
    console.print(f"[bold]Gate verdict:[/bold] [{'green' if gate_verdict == 'PASS' else 'red'}]{gate_verdict}[/]")
    console.print(f"[dim]Elapsed: {elapsed}s[/dim]")

    # ── Step 3: Switch or block ───────────────────────────────────────────────
    if gate_verdict == "PASS":
        if dry_run:
            decision = "DRY_RUN_WOULD_DEPLOY"
            console.print("[bold yellow]⚡ Dry run — would switch to green. Skipping actual switch.[/bold yellow]")
        else:
            switched = _do_switch(version)
            decision = "DEPLOYED" if switched else "SWITCH_FAILED"
            if switched:
                console.print(f"\n[bold green]✅ DEPLOYED[/bold green] — version [cyan]{version}[/cyan] is now live (green slot).")
            else:
                console.print("\n[bold red]⛔ Switch failed[/bold red] — gate passed but slot switch errored. Manual intervention required.")
    else:
        decision = "BLOCKED"
        console.print(f"\n[bold red]⛔ GATE BLOCKED[/bold red] — version [cyan]{version}[/cyan] failed safety gate. Blue slot remains live.")

    # ── Audit record ──────────────────────────────────────────────────────────
    record_path = _write_gate_record(version, _variant, score_report, gate_verdict, decision)
    console.print(f"\n[bold]Audit record:[/bold] {record_path}")

    raise typer.Exit(code=0 if gate_verdict == "PASS" else 1)


if __name__ == "__main__":
    app()
