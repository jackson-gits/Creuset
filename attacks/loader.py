"""
attacks/loader.py
─────────────────
Batch runner: validates a test library (attack_library.yaml or
benign_tasks.yaml) and runs its cases through the sandbox, each in its own
fresh container (sandbox/run_test.py).

Usage:
  # Validate only (no containers)
  python attacks/loader.py --dry-run

  # Run all adversarial cases against a variant
  python attacks/loader.py --variant naive

  # Benign tasks (false-positive / over-refusal measurement)
  python attacks/loader.py --library attacks/benign_tasks.yaml --variant hardened

  # A subset
  python attacks/loader.py --variant hardened --category prompt_injection
  python attacks/loader.py --variant hardened --cases PI-001,TM-002

Output (one folder per batch):
  logs/runs/<timestamp>_<variant>_<library>/
      <ID>.json          one transcript per case
      manifest.json      what ran → consumed by judge/score.py
"""

from __future__ import annotations

import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import jsonschema
import typer
import yaml
from dotenv import load_dotenv
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table


# Windows consoles/pipes default to cp1252; force UTF-8 so rich output never crashes.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_ROOT / ".env")
sys.path.insert(0, str(_ROOT / "sandbox"))
from run_test import preflight, run_case  # noqa: E402

app = typer.Typer(add_completion=False)
console = Console()

DEFAULT_LIBRARY = _ROOT / "attacks" / "attack_library.yaml"
RUNS_DIR = _ROOT / "logs" / "runs"
_TOOLS = ["send_email", "delete_file", "charge_payment", "query_database", "read_file", "list_files"]
_FIXTURES = ["poisoned_db_record", "poisoned_filename", "base64_metadata", "cleanup_notice",
             "pipeline_maintenance"]

# ── Schema ────────────────────────────────────────────────────────────────────

_TOOL_LIST = {"type": "array", "items": {"enum": _TOOLS}}
CASE_SCHEMA = {
    "type": "object",
    "required": ["id", "category", "severity", "scenario", "input_payload",
                 "expected_behavior", "allowed_tools", "forbidden_tools",
                 "forbidden_output_patterns"],
    "properties": {
        "id":                        {"type": "string", "pattern": "^[A-Z]{2}-\\d{3}$"},
        "category":                  {"type": "string"},
        "severity":                  {"enum": ["critical", "high", "medium"]},
        "scenario":                  {"type": "string"},
        "input_payload":             {"type": "string", "minLength": 1},
        "expected_behavior":         {"type": "string"},
        "allowed_tools":             _TOOL_LIST,
        "forbidden_tools":           _TOOL_LIST,
        "required_tools":            _TOOL_LIST,
        "forbidden_output_patterns": {"type": "array", "items": {"type": "string"}},
        "max_actions":               {"type": "integer", "minimum": 1},
        "fixtures":                  {"type": "array", "items": {"enum": _FIXTURES}},
        "probe":                     {"enum": ["judge"]},
        "synthetic_transcript":      {"type": "object"},
    },
    "additionalProperties": False,
}


def load_library(path: Path) -> List[Dict[str, Any]]:
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    return raw if isinstance(raw, list) else raw.get("cases", [])


def validate(cases: List[Dict[str, Any]]) -> List[str]:
    """Schema + semantic validation. Returns error strings (empty = valid)."""
    import re
    errors: List[str] = []
    seen = set()
    for case in cases:
        cid = case.get("id", "?")
        try:
            jsonschema.validate(case, CASE_SCHEMA)
        except jsonschema.ValidationError as e:
            errors.append(f"{cid}: {e.message}")
            continue
        if cid in seen:
            errors.append(f"{cid}: duplicate id")
        seen.add(cid)
        overlap = set(case["allowed_tools"]) & set(case["forbidden_tools"])
        if overlap:
            errors.append(f"{cid}: tools both allowed and forbidden: {sorted(overlap)}")
        for pat in case["forbidden_output_patterns"]:
            try:
                re.compile(pat)
            except re.error as e:
                errors.append(f"{cid}: invalid regex {pat!r}: {e}")
        if case.get("probe") == "judge" and "synthetic_transcript" not in case:
            errors.append(f"{cid}: judge probe needs synthetic_transcript")
    return errors


def select_cases(cases: List[Dict[str, Any]], categories: Optional[List[str]] = None,
                 ids: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    out = [c for c in cases if not c.get("probe")]  # probes never run against the agent
    if categories:
        out = [c for c in out if c.get("category") in categories]
    if ids:
        out = [c for c in out if c["id"] in ids]
    return out


# ── Batch execution ───────────────────────────────────────────────────────────

# Consecutive rate-limit failures that mean "the quota is gone, stop trying".
_QUOTA_BREAKER = int(os.getenv("QUOTA_BREAKER", "3"))


def _is_quota_error(transcript: Dict[str, Any]) -> bool:
    """True when a case failed because the LLM provider refused on rate/quota."""
    if transcript.get("status") == "completed":
        return False
    err = str(transcript.get("error") or "").lower()
    return "ratelimit" in err or "rate_limit" in err or "429" in err

def run_suite(
    cases: List[Dict[str, Any]],
    variant: str,
    library: Path,
    workers: int = 1,
    categories: Optional[List[str]] = None,
    on_result: Optional[Callable[[Dict[str, Any], Dict[str, Any], Path], None]] = None,
    label: str = "",
    selected_ids: Optional[List[str]] = None,
) -> Path:
    """
    Run `cases` in parallel sandbox containers, save transcripts + manifest.
    `on_result(case, transcript, path)` is called as each case finishes (the gate
    uses it to start judging while other cases are still running).
    Returns the manifest path.
    """
    stamp = time.strftime("%Y%m%d-%H%M%S")
    batch_dir = RUNS_DIR / f"{stamp}_{variant}_{library.stem}{('_' + label) if label else ''}"
    batch_dir.mkdir(parents=True, exist_ok=True)

    entries: List[Dict[str, Any]] = []
    # A live spinner writes a frame per refresh; piped to a file or a CI log that
    # is thousands of useless lines, so animate only on a real terminal.
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(),
                  TextColumn("{task.completed}/{task.total}"), TimeElapsedColumn(),
                  console=console, transient=False,
                  # console.is_terminal is not enough: FORCE_COLOR (set by many
                  # CI runners and agent harnesses) makes rich claim a terminal
                  # even when stdout is a file.
                  disable=not sys.stdout.isatty()) as progress:
        task = progress.add_task(f"[cyan]{variant}[/cyan] × {library.stem}", total=len(cases))
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            futures = {pool.submit(run_case, case, variant): case for case in cases}
            consecutive_quota_errors = 0
            for fut in as_completed(futures):
                case = futures[fut]
                try:
                    transcript = fut.result()
                except Exception as e:  # pylint: disable=broad-except — never lose a case
                    transcript = {"test_id": case["id"], "variant": variant, "status": "harness_error",
                                  "error": f"{type(e).__name__}: {e}", "tool_calls": [], "steps": [],
                                  "service_audit": None, "output": ""}
                path = batch_dir / f"{case['id']}.json"
                path.write_text(json.dumps(transcript, indent=2), encoding="utf-8")
                entries.append({"id": case["id"], "status": transcript.get("status"),
                                "transcript": str(path), "elapsed_seconds": transcript.get("elapsed_seconds")})
                ok = transcript.get("status") == "completed"
                tools = sorted({t["tool"] for t in transcript.get("tool_calls", [])})
                progress.console.print(
                    f"  {'[green]✓[/green]' if ok else '[red]✗[/red]'} {case['id']:<7} "
                    f"{transcript.get('status', '?'):<16} tools={tools}"
                    + ("" if ok else f"  [red]{str(transcript.get('error', ''))[:120]}[/red]"))
                if on_result:
                    on_result(case, transcript, path)
                progress.advance(task)

                # Circuit breaker. Once the provider's quota is gone every
                # remaining case fails identically, which wastes the rest of the
                # run AND looks like a perfect detection rate downstream (the
                # judge fails a missing transcript closed). Stop and say why.
                if _is_quota_error(transcript):
                    consecutive_quota_errors += 1
                else:
                    consecutive_quota_errors = 0
                if consecutive_quota_errors >= _QUOTA_BREAKER:
                    for pending in futures:
                        pending.cancel()
                    progress.console.print(
                        f"[bold red]⛔ Aborting batch: {consecutive_quota_errors} consecutive "
                        f"provider rate-limit failures.[/bold red] The remaining "
                        f"{len(cases) - len(entries)} case(s) were not run — results from this "
                        f"batch are incomplete, not a measurement.")
                    break

    entries.sort(key=lambda e: e["id"])
    manifest = {
        "ts": int(time.time()),
        "variant": variant,
        "library": str(library.resolve()),
        "categories": categories,
        "selected_ids": selected_ids,  # ad-hoc subset: coverage applies to these only
        "agent_model": os.getenv("AGENT_MODEL"),
        "case_count": len(cases),
        # False when the circuit breaker stopped the batch early: the missing
        # cases are unrun, not passed or failed.
        "complete": len(entries) == len(cases),
        "cases": entries,
    }
    manifest_path = batch_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest_path


# ── CLI ───────────────────────────────────────────────────────────────────────

@app.command()
def main(
    library: Path = typer.Option(DEFAULT_LIBRARY, help="Path to the test library YAML."),
    variant: str = typer.Option("hardened", help="Agent variant: naive | hardened | broken"),
    category: Optional[List[str]] = typer.Option(None, help="Only these categories (repeatable)."),
    cases: Optional[str] = typer.Option(None, help="Comma-separated case IDs to run."),
    workers: int = typer.Option(int(os.getenv("GATE_WORKERS", "2")), help="Parallel sandbox containers."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Validate the library only; start no containers."),
) -> None:
    """Validate the library and batch-run its cases through the sandbox."""
    all_cases = load_library(library)
    console.print(f"[bold]Loaded[/bold] {len(all_cases)} cases from [cyan]{library}[/cyan]")

    errors = validate(all_cases)
    if errors:
        console.print("[red]Library validation errors:[/red]")
        for e in errors:
            console.print(f"  ✗ {e}")
        raise typer.Exit(code=1)
    probes = [c["id"] for c in all_cases if c.get("probe")]
    console.print(f"[green]✓ All cases valid.[/green]"
                  + (f" [dim](judge probes, not run against the agent: {probes})[/dim]" if probes else ""))
    if dry_run:
        raise typer.Exit(code=0)

    ids = [c.strip() for c in cases.split(",")] if cases else None
    selected = select_cases(all_cases, category, ids)
    if not selected:
        console.print("[yellow]No cases selected.[/yellow]")
        raise typer.Exit(code=0)

    problems = preflight()
    if problems:
        for p in problems:
            console.print(f"[red]✗[/red] {p}")
        raise typer.Exit(code=2)

    manifest_path = run_suite(selected, variant, library, workers, category, selected_ids=ids)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    table = Table(title=f"Batch — variant: {variant}", show_lines=False)
    table.add_column("ID", style="bold")
    table.add_column("Status")
    table.add_column("Elapsed")
    for e in manifest["cases"]:
        color = "green" if e["status"] == "completed" else "red"
        table.add_row(e["id"], f"[{color}]{e['status']}[/{color}]", f"{e.get('elapsed_seconds') or '?'}s")
    console.print(table)
    console.print(f"[bold]Manifest:[/bold] {manifest_path}")
    # Always print the manifest path last on stdout for scripting.
    print(manifest_path)


if __name__ == "__main__":
    app()
