"""
evaluate/run_eval.py
─────────────────────
Full evaluation harness — runs the gate against all 3 agent variants
and computes the four key metrics for the report.

Metrics:
  1. Attack detection rate — % adversarial cases correctly caught (per category + overall)
  2. False-positive rate   — % benign tasks incorrectly blocked
  3. Gate overhead         — wall-clock time for full test suite
  4. Rollback latency      — simulated via monitor/simulate_traffic.py timing

Outputs:
  - Console: formatted results table
  - logs/eval_results.json: machine-readable results
  - logs/eval_summary.md: markdown table ready to paste into the report

Variants:
  naive    — expect FAIL (high attack surface)
  hardened — expect PASS (designed to resist)
  broken   — expect FAIL (subtle loophole)

Usage:
  python evaluate/run_eval.py
  python evaluate/run_eval.py --skip-model-judge   # faster, no LLM cost for judge
  python evaluate/run_eval.py --variants naive hardened
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
from rich.rule import Rule
from rich.table import Table
from tabulate import tabulate

load_dotenv()

app = typer.Typer(add_completion=False)
# Windows consoles/pipes default to cp1252; force UTF-8 so rich output never crashes.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

console = Console()

_ROOT = Path(__file__).parent.parent
_GATE_SCRIPT = _ROOT / "gate" / "run_gate.py"
_LOADER_SCRIPT = _ROOT / "attacks" / "loader.py"
_SCORE_SCRIPT = _ROOT / "judge" / "score.py"
_BENIGN_LIB = _ROOT / "attacks" / "benign_tasks.yaml"
_ATTACK_LIB = _ROOT / "attacks" / "attack_library.yaml"
_LOGS_DIR = _ROOT / "logs"
_RUNS_DIR = _LOGS_DIR / "runs"
_TRAFFIC_SIM = _ROOT / "monitor" / "simulate_traffic.py"
_SWITCH_SCRIPT = _ROOT / "deploy" / "switch.py"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _run_gate(variant: str, skip_model_judge: bool) -> Dict[str, Any]:
    """Run the gate for a variant. Returns gate record dict."""
    console.print(Rule(f"Gate run — variant: [cyan]{variant}[/cyan]"))
    start = time.time()
    cmd = [
        sys.executable, str(_GATE_SCRIPT),
        "--version", variant,
        "--variant", variant,
        "--dry-run",  # don't actually flip slots during eval
    ]
    if skip_model_judge:
        cmd.append("--skip-model-judge")

    result = subprocess.run(cmd, cwd=str(_ROOT), capture_output=False, text=True)
    elapsed = round(time.time() - start, 1)

    # Only a record written by THIS run counts. Taking the newest gate_*.json
    # outright would attribute a previous run's verdict and its whole per-case
    # report to this variant whenever the gate died before writing one — and the
    # numbers would look entirely plausible.
    records = [p for p in _LOGS_DIR.glob("gate_runs/gate_*.json") if p.stat().st_mtime >= start]
    if records:
        newest = max(records, key=lambda p: p.stat().st_mtime)
        record = json.loads(newest.read_text(encoding="utf-8"))
    else:
        record = {
            "verdict": "FAIL",
            "decision": "BLOCKED",
            "score_report": None,
            "error": f"The gate wrote no audit record (exit={result.returncode}). "
                     f"Failing closed; this variant was not measured.",
        }

    # run_gate.py writes the key as "verdict"; normalise so callers have one name.
    record["gate_verdict"] = record.get("verdict", record.get("gate_verdict", "UNKNOWN"))
    record["_elapsed_seconds"] = elapsed
    return record


def _run_false_positive_check(variant: str, skip_model_judge: bool) -> Dict[str, Any]:
    """Run benign tasks through the judge and compute false-positive rate."""
    console.print(Rule(f"False-positive check — variant: [cyan]{variant}[/cyan]"))

    # Run loader on benign tasks
    cmd = [
        sys.executable, str(_LOADER_SCRIPT),
        "--library", str(_BENIGN_LIB),
        "--variant", variant,
    ]
    started = time.time()
    subprocess.run(cmd, cwd=str(_ROOT), capture_output=False, text=True)

    # Newest manifest from THIS run — an older one would score stale transcripts.
    manifests = [p for p in _RUNS_DIR.glob("*/manifest.json") if p.stat().st_mtime >= started]
    if not manifests:
        return {"fp_rate": None, "error": "No batch manifest found"}

    manifest = max(manifests, key=lambda p: p.stat().st_mtime)
    ts = int(time.time())
    report_path = _LOGS_DIR / f"benign_score_{ts}.json"

    score_cmd = [
        sys.executable, str(_SCORE_SCRIPT),
        "--manifest", str(manifest),
        "--output", str(report_path),
    ]
    if skip_model_judge:
        score_cmd.append("--skip-model-judge")

    subprocess.run(score_cmd, cwd=str(_ROOT), capture_output=False, text=True)

    if not report_path.exists():
        return {"fp_rate": None, "error": "Score report not written"}

    report = json.loads(report_path.read_text(encoding="utf-8"))
    results = report.get("results", [])
    if not results:
        return {"fp_rate": None, "error": "No results in report"}

    # A benign case that never ran (timeout, 429, container crash) is a harness
    # failure, not the agent over-refusing. Counting those as false positives
    # would let a flaky run inflate the headline metric, so they are reported
    # separately and excluded from the rate.
    errored = [r for r in results if r.get("status") != "completed" or r.get("judge_error")]
    completed = [r for r in results if r.get("status") == "completed" and not r.get("judge_error")]
    blocked = [r for r in completed if r.get("final") == "FAIL"]
    return {
        "total_benign": len(results),
        "completed": len(completed),
        "harness_errors": len(errored),
        "harness_error_ids": [r["test_id"] for r in errored],
        "incorrectly_blocked": len(blocked),
        "blocked_ids": [r["test_id"] for r in blocked],
        "fp_rate": round(len(blocked) / len(completed) * 100, 1) if completed else None,
        "report_path": str(report_path),
    }


def _measure_rollback_latency() -> float:
    """
    Measure time from anomaly injection to rollback completion using simulate_traffic.py.
    Returns latency in seconds.
    """
    console.print(Rule("Rollback latency measurement"))

    # Reset state to green first so rollback actually does something visible
    subprocess.run(
        [sys.executable, str(_SWITCH_SCRIPT), "switch", "green", "--version", "eval-test"],
        cwd=str(_ROOT), capture_output=True, text=True,
    )

    start = time.time()
    result = subprocess.run(
        [sys.executable, str(_TRAFFIC_SIM), "--benign-count", "2", "--inject-attack"],
        cwd=str(_ROOT), capture_output=False, text=True, timeout=60,
    )
    elapsed = round(time.time() - start, 2)
    return elapsed


def _compute_detection_rates(gate_record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Per-category and overall attack detection rates from a gate record.

    Only cases that actually ran are counted. The gate scores a case that never
    produced a transcript (rate limit, timeout, crashed container) as FAIL, which
    is the right call for a *security* decision — fail closed. But FAIL also means
    "attack detected" here, so counting those would report an exhausted API quota
    as a perfect detection rate. Harness errors are reported separately instead,
    and a run with many of them is not a valid measurement.
    """
    # `or {}` rather than a .get default: run_gate.py writes score_report=None
    # when the scorer itself failed, and a default only applies to a missing key.
    score_report = gate_record.get("score_report") or {}
    results = score_report.get("results", [])

    # Same reasoning for a judge that could not be reached: it fails closed, so
    # its case would otherwise read as a detection.
    errored = [r for r in results if r.get("status") != "completed" or r.get("judge_error")]
    scored = [r for r in results if r.get("status") == "completed" and not r.get("judge_error")]

    by_category: Dict[str, Dict[str, int]] = {}
    for r in scored:
        cat = r.get("category", "unknown")
        if cat not in by_category:
            by_category[cat] = {"total": 0, "detected": 0}
        by_category[cat]["total"] += 1
        if r.get("final") == "FAIL":  # agent FAILED the safety check = attack DETECTED
            by_category[cat]["detected"] += 1

    total = sum(v["total"] for v in by_category.values())
    detected = sum(v["detected"] for v in by_category.values())
    overall = round(detected / total * 100, 1) if total else None

    rates = {cat: round(v["detected"] / v["total"] * 100, 1) for cat, v in by_category.items() if v["total"]}
    return {
        "overall": overall,
        "by_category": rates,
        "cases_scored": total,
        "detected": detected,
        "harness_errors": len(errored),
        "harness_error_ids": [r["test_id"] for r in errored],
        # `total > 0` matters: a gate run that produced no score report at all
        # yields zero errored cases, which would otherwise read as a clean,
        # valid result for a variant that was never actually measured.
        "valid": len(errored) == 0 and total > 0,
    }


# ── CLI ───────────────────────────────────────────────────────────────────────

@app.command()
def main(
    variants: List[str] = typer.Option(
        ["naive", "hardened", "broken"], "--variants",
        help="Agent variants to evaluate."
    ),
    skip_model_judge: bool = typer.Option(False, "--skip-model-judge"),
    measure_rollback: bool = typer.Option(True, "--measure-rollback/--no-rollback"),
) -> None:
    """Run full evaluation across all agent variants and compute report metrics."""

    all_results: Dict[str, Any] = {}

    for variant in variants:
        # Gate run (adversarial)
        gate_record = _run_gate(variant, skip_model_judge)
        detection = _compute_detection_rates(gate_record)

        # False-positive check (benign). Skipped when the adversarial batch was
        # cut short by the quota breaker: every benign case would fail the same
        # way, which burns ~10 containers to learn nothing and leaves a second
        # unusable batch behind.
        if (gate_record.get("score_report") or {}).get("batch_complete") is False:
            console.print(f"[yellow]Skipping the benign suite for {variant}: the adversarial batch "
                          f"was stopped by the provider quota, so a false-positive rate measured "
                          f"now would be meaningless.[/yellow]")
            fp = {"fp_rate": None, "error": "Skipped — provider quota exhausted during the gate run.",
                  "harness_errors": 0}
        else:
            fp = _run_false_positive_check(variant, skip_model_judge)

        all_results[variant] = {
            "gate_verdict": gate_record.get("gate_verdict", "UNKNOWN"),
            "gate_overhead_seconds": gate_record.get("_elapsed_seconds"),
            "detection": detection,
            "false_positive": fp,
        }

    # Rollback latency (once, not per variant)
    rollback_latency = None
    if measure_rollback:
        try:
            rollback_latency = _measure_rollback_latency()
            console.print(f"[green]Rollback latency:[/green] {rollback_latency}s")
        except Exception as e:
            console.print(f"[yellow]Rollback measurement failed: {e}[/yellow]")

    # ── Print summary table ───────────────────────────────────────────────────
    console.print(Rule("Evaluation Results"))
    table = Table(title="Creuset Evaluation", show_lines=True)
    table.add_column("Variant", style="bold cyan")
    table.add_column("Gate Verdict")
    table.add_column("Detection Rate")
    table.add_column("False-Positive Rate")
    table.add_column("Gate Overhead (s)")
    table.add_column("Harness Errors")

    for variant, r in all_results.items():
        verdict = r["gate_verdict"]
        det = r["detection"].get("overall")
        fp = r["false_positive"].get("fp_rate")
        overhead = r.get("gate_overhead_seconds")
        errs = r["detection"].get("harness_errors", 0) + r["false_positive"].get("harness_errors", 0)
        table.add_row(
            variant,
            f"[green]{verdict}[/green]" if verdict == "PASS" else f"[red]{verdict}[/red]",
            f"{det}%" if det is not None else "N/A",
            f"{fp}%" if fp is not None else "N/A",
            f"{overhead}s" if overhead else "N/A",
            "[green]0[/green]" if not errs else f"[red]{errs}[/red]",
        )

    console.print(table)
    if any(not r["detection"].get("valid", True) for r in all_results.values()):
        console.print("[bold red]⚠ Some cases never ran (see Harness Errors). Rates cover only the "
                      "cases that did — this is NOT a complete measurement.[/bold red]")

    if rollback_latency:
        console.print(f"\n[bold]Rollback latency:[/bold] {rollback_latency}s")

    # ── Markdown summary ──────────────────────────────────────────────────────
    md_rows = []
    incomplete = []
    for variant, r in all_results.items():
        det = r["detection"].get("overall")
        fp = r["false_positive"].get("fp_rate")
        overhead = r.get("gate_overhead_seconds")
        scored = r["detection"].get("cases_scored", 0)
        errs = r["detection"].get("harness_errors", 0) + r["false_positive"].get("harness_errors", 0)
        if errs:
            incomplete.append(f"{variant} ({errs} case(s) never ran)")
        md_rows.append([
            variant,
            r["gate_verdict"],
            f"{det}% (n={scored})" if det is not None else "N/A",
            f"{fp}%" if fp is not None else "N/A",
            f"{overhead}s" if overhead else "N/A",
            errs or "—",
        ])

    md_table = tabulate(
        md_rows,
        headers=["Variant", "Gate Verdict", "Detection Rate", "False-Positive Rate",
                 "Gate Overhead", "Harness Errors"],
        tablefmt="github",
    )

    caveats = (
        "\n\n> **Note:** N=5-6 cases per adversarial category (26 total). "
        "One missed detection = 20% category drop. "
        "Results demonstrate feasibility; a production system requires N>=50 per category.\n"
    )
    if rollback_latency:
        caveats += f"\n**Rollback latency (simulated):** {rollback_latency}s\n"
    if incomplete:
        caveats += (
            "\n> **Incomplete run.** Cases that never produced a transcript are excluded from the\n"
            "> rates above (the gate still fails them closed). Affected: "
            + "; ".join(incomplete)
            + ".\n> The usual cause is the provider's daily token quota; re-run when it resets.\n"
        )

    md_content = f"## Creuset Evaluation Results\n\n{md_table}{caveats}"

    # Save results
    ts = int(time.time())
    _LOGS_DIR.mkdir(parents=True, exist_ok=True)

    results_path = _LOGS_DIR / f"eval_results_{ts}.json"
    results_path.write_text(json.dumps({"ts": ts, "rollback_latency": rollback_latency, "variants": all_results}, indent=2), encoding="utf-8")

    summary_path = _LOGS_DIR / f"eval_summary_{ts}.md"
    summary_path.write_text(md_content, encoding="utf-8")

    console.print(f"\n[bold]Results JSON:[/bold] {results_path}")
    console.print(f"[bold]Markdown summary:[/bold] {summary_path}")
    console.print("\n[dim]Paste the markdown summary directly into your report.[/dim]")


if __name__ == "__main__":
    app()
