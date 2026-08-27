"""
attacks/loader.py
─────────────────
Batch runner: reads attack_library.yaml (or benign_tasks.yaml),
validates each case against the schema, and feeds them one-by-one
into the sandbox harness (sandbox/run_test.py).

Usage:
  # Validate only (no containers spun up)
  python attacks/loader.py --dry-run

  # Run all adversarial cases against the naive agent variant
  python attacks/loader.py --variant naive

  # Run benign tasks (for false-positive measurement)
  python attacks/loader.py --library attacks/benign_tasks.yaml --variant hardened

  # Run a specific category only
  python attacks/loader.py --variant hardened --category prompt_injection

Output:
  - Transcript JSON files in logs/
  - A manifest file: logs/batch_<timestamp>.json listing all transcript paths
    (consumed by judge/score.py)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import jsonschema
import typer
import yaml
from dotenv import load_dotenv
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

load_dotenv()

app = typer.Typer(add_completion=False)
console = Console()

_ROOT = Path(__file__).parent.parent
_DEFAULT_LIBRARY = _ROOT / "attacks" / "attack_library.yaml"
_LOGS_DIR = _ROOT / "logs"
_RUN_TEST = _ROOT / "sandbox" / "run_test.py"

# ── Schema ────────────────────────────────────────────────────────────────────

_CASE_SCHEMA = {
    "type": "object",
    "required": ["id", "category", "severity", "scenario", "input_payload",
                 "expected_behavior", "allowed_tools", "forbidden_tools",
                 "forbidden_output_patterns"],
    "properties": {
        "id":                        {"type": "string"},
        "category":                  {"type": "string"},
        "severity":                  {"enum": ["critical", "high", "medium"]},
        "scenario":                  {"type": "string"},
        "input_payload":             {"type": "string"},
        "expected_behavior":         {"type": "string"},
        "allowed_tools":             {"type": "array", "items": {"type": "string"}},
        "forbidden_tools":           {"type": "array", "items": {"type": "string"}},
        "forbidden_output_patterns": {"type": "array", "items": {"type": "string"}},
        "max_actions":               {"type": "integer"},
    },
    "additionalProperties": True,
}


def _validate_case(case: Dict[str, Any]) -> List[str]:
    """Validate a case dict against the schema. Returns a list of error messages."""
    errors: List[str] = []
    try:
        jsonschema.validate(case, _CASE_SCHEMA)
    except jsonschema.ValidationError as e:
        errors.append(f"{case.get('id', '?')}: {e.message}")
    return errors


def _load_library(path: Path) -> List[Dict[str, Any]]:
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    return raw if isinstance(raw, list) else raw.get("cases", [])


def _write_scenario(case: Dict[str, Any], tmp_dir: str) -> str:
    p = os.path.join(tmp_dir, f"{case['id']}.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(case, f)
    return p


def _run_one(case: Dict[str, Any], variant: str) -> Dict[str, Any]:
    """Run a single case through the sandbox harness subprocess."""
    with tempfile.TemporaryDirectory() as tmp:
        scenario_path = _write_scenario(case, tmp)
        cmd = [
            sys.executable, str(_RUN_TEST),
            "--test-id", case["id"],
            "--variant", variant,
            "--no-save",   # loader handles saving
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=int(os.getenv("SANDBOX_TIMEOUT_SECONDS", "120")) + 10,
                cwd=str(_ROOT),
                encoding="utf-8",
                errors="replace",
            )
            # run_test.py prints JSON transcript on stdout
            stdout = proc.stdout.strip()
            try:
                return json.loads(stdout)
            except json.JSONDecodeError:
                return {
                    "test_id": case["id"],
                    "variant": variant,
                    "status": "loader_parse_error",
                    "error": f"Could not parse run_test output. stdout={stdout[:200]}",
                    "tool_calls": [],
                    "steps": [],
                }
        except subprocess.TimeoutExpired:
            return {
                "test_id": case["id"],
                "variant": variant,
                "status": "loader_timeout",
                "error": "loader subprocess timed out",
                "tool_calls": [],
                "steps": [],
            }


def _save_transcript(transcript: Dict[str, Any], variant: str) -> Path:
    _LOGS_DIR.mkdir(parents=True, exist_ok=True)
    ts = int(time.time())
    fname = f"{transcript['test_id']}_{variant}_{ts}.json"
    p = _LOGS_DIR / fname
    p.write_text(json.dumps(transcript, indent=2), encoding="utf-8")
    return p


# ── CLI ───────────────────────────────────────────────────────────────────────

@app.command()
def main(
    library: Path = typer.Option(_DEFAULT_LIBRARY, help="Path to the attack library YAML."),
    variant: str = typer.Option("hardened", help="Agent variant: naive | hardened | broken"),
    category: Optional[str] = typer.Option(None, help="Filter to a single category."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Validate schema only, don't run containers."),
) -> None:
    """Batch-run all (or filtered) test cases through the sandbox."""

    cases = _load_library(library)
    console.print(f"[bold]Loaded[/bold] {len(cases)} cases from [cyan]{library}[/cyan]")

    # Schema validation
    all_errors: List[str] = []
    for case in cases:
        all_errors.extend(_validate_case(case))

    if all_errors:
        console.print("[red]Schema validation errors:[/red]")
        for e in all_errors:
            console.print(f"  ✗ {e}")
        raise typer.Exit(code=1)

    console.print("[green]✓ All cases pass schema validation.[/green]")

    if dry_run:
        console.print("[bold]Dry run complete. No containers started.[/bold]")
        raise typer.Exit(code=0)

    # Filter by category
    if category:
        cases = [c for c in cases if c.get("category") == category]
        console.print(f"[dim]Filtered to category '[bold]{category}[/bold]': {len(cases)} cases[/dim]")

    if not cases:
        console.print("[yellow]No cases to run.[/yellow]")
        raise typer.Exit(code=0)

    # Batch run
    results: List[Dict[str, Any]] = []
    transcript_paths: List[str] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(f"Running {len(cases)} cases...", total=len(cases))

        for case in cases:
            progress.update(task, description=f"[cyan]{case['id']}[/cyan] ({variant})")
            transcript = _run_one(case, variant)
            path = _save_transcript(transcript, variant)
            transcript_paths.append(str(path))
            results.append({"id": case["id"], "status": transcript.get("status"), "path": str(path)})
            progress.advance(task)

    # Results table
    table = Table(title=f"Batch run — variant: {variant}", show_lines=True)
    table.add_column("ID", style="bold")
    table.add_column("Status")
    table.add_column("Transcript")

    for r in results:
        color = "green" if r["status"] == "completed" else "red"
        table.add_row(r["id"], f"[{color}]{r['status']}[/{color}]", Path(r["path"]).name)

    console.print(table)

    # Save manifest
    ts = int(time.time())
    manifest_path = _LOGS_DIR / f"batch_{ts}.json"
    manifest = {
        "ts": ts,
        "variant": variant,
        "library": str(library),
        "case_count": len(cases),
        "transcripts": transcript_paths,
    }
    _LOGS_DIR.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    console.print(f"\n[bold]Manifest saved:[/bold] {manifest_path}")


if __name__ == "__main__":
    app()
