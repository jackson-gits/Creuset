"""
sandbox/run_test.py
────────────────────
Per-test harness: spins up a fresh agent container per test case,
feeds it a scenario via a mounted JSON file, captures the transcript,
tears the container down, and saves the result to logs/.

Pattern (Fix #2 from reviewer):
  docker run --rm
    --network creuset-net
    --memory=512m --cpus=1.0
    --env-file .env
    -v /abs/path/to/scenario.json:/scenario.json:ro
    creuset-agent:latest
    python run_agent.py --scenario-file /scenario.json --variant <variant>

One container per test. Destroyed after. Timeout enforced by Python subprocess.

Usage:
  python sandbox/run_test.py --test-id PI-001 --variant naive
  python sandbox/run_test.py --scenario-file attacks/scenarios/PI-001.json --variant hardened
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Optional

import typer
import yaml
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel

load_dotenv()

app = typer.Typer(add_completion=False)
console = Console(stderr=True)

# ── Paths ─────────────────────────────────────────────────────────────────────
_ROOT = Path(__file__).parent.parent
_LOGS_DIR = _ROOT / "logs"
_ATTACK_LIB = _ROOT / "attacks" / "attack_library.yaml"
_ENV_FILE = _ROOT / ".env"
_AGENT_IMAGE = os.getenv("AGENT_IMAGE_TAG", "creuset-agent:latest")
_TIMEOUT = int(os.getenv("SANDBOX_TIMEOUT_SECONDS", "120"))


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_scenario_by_id(test_id: str) -> Dict[str, Any]:
    """Load a test case from attack_library.yaml by ID."""
    with open(_ATTACK_LIB, encoding="utf-8") as f:
        library = yaml.safe_load(f)

    # Support both top-level list and {"cases": [...]} format
    cases = library if isinstance(library, list) else library.get("cases", [])
    for case in cases:
        if case.get("id") == test_id:
            return case
    raise ValueError(f"Test ID '{test_id}' not found in attack library.")


def _write_scenario_file(scenario: Dict[str, Any], tmp_dir: str) -> str:
    """Write scenario dict to a temp JSON file; return absolute path."""
    path = os.path.join(tmp_dir, "scenario.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(scenario, f, indent=2)
    return path


def _run_container(
    scenario_path: str,
    variant: str,
    test_id: str,
) -> Dict[str, Any]:
    """
    Spin up a fresh agent container, feed it the scenario, capture output.
    Returns the parsed transcript dict.
    """
    # Normalise path for Docker volume mount (Windows paths need forward slashes)
    scenario_abs = Path(scenario_path).resolve().as_posix()

    cmd = [
        "docker", "run", "--rm",
        "--network", "creuset-net",
        "--memory", "512m",
        "--cpus", "1.0",
        "--env-file", str(_ENV_FILE.resolve()),
        "-v", f"{scenario_abs}:/scenario.json:ro",
        _AGENT_IMAGE,
        "--scenario-file", "/scenario.json",
        "--variant", variant,
    ]

    console.print(f"[dim]Running:[/dim] {' '.join(cmd)}")

    start_ts = time.time()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_TIMEOUT,
            encoding="utf-8",
            errors="replace",
        )
        elapsed = time.time() - start_ts

        stdout = proc.stdout.strip()
        stderr = proc.stderr.strip()

        if proc.returncode != 0 and not stdout:
            # Container failed without producing a transcript
            return {
                "test_id": test_id,
                "variant": variant,
                "status": "container_error",
                "output": "",
                "tool_calls": [],
                "steps": [],
                "llm_calls_made": 0,
                "llm_calls_limit": int(os.getenv("MAX_LLM_CALLS", "15")),
                "budget_ok": False,
                "error": f"Container exited {proc.returncode}. stderr: {stderr}",
                "elapsed_seconds": round(elapsed, 2),
            }

        # Parse the JSON transcript from stdout
        try:
            transcript = json.loads(stdout)
        except json.JSONDecodeError:
            transcript = {
                "test_id": test_id,
                "variant": variant,
                "status": "parse_error",
                "output": stdout,
                "tool_calls": [],
                "steps": [],
                "llm_calls_made": 0,
                "llm_calls_limit": int(os.getenv("MAX_LLM_CALLS", "15")),
                "budget_ok": False,
                "error": f"Could not parse JSON transcript. stderr: {stderr}",
            }

        transcript["elapsed_seconds"] = round(elapsed, 2)
        if stderr:
            transcript["stderr"] = stderr
        return transcript

    except subprocess.TimeoutExpired:
        elapsed = time.time() - start_ts
        return {
            "test_id": test_id,
            "variant": variant,
            "status": "timeout",
            "output": "",
            "tool_calls": [],
            "steps": [],
            "llm_calls_made": 0,
            "llm_calls_limit": int(os.getenv("MAX_LLM_CALLS", "15")),
            "budget_ok": False,
            "error": f"Container timed out after {_TIMEOUT}s",
            "elapsed_seconds": round(elapsed, 2),
        }


def _save_transcript(transcript: Dict[str, Any], variant: str) -> Path:
    """Write transcript JSON to logs/ and return the path."""
    _LOGS_DIR.mkdir(parents=True, exist_ok=True)
    test_id = transcript.get("test_id", "UNKNOWN")
    ts = int(time.time())
    filename = f"{test_id}_{variant}_{ts}.json"
    out_path = _LOGS_DIR / filename
    out_path.write_text(json.dumps(transcript, indent=2), encoding="utf-8")
    return out_path


# ── CLI ───────────────────────────────────────────────────────────────────────

@app.command()
def main(
    test_id: Optional[str] = typer.Option(
        None, "--test-id", help="Test case ID from attack_library.yaml (e.g. PI-001)"
    ),
    scenario_file: Optional[Path] = typer.Option(
        None, "--scenario-file", help="Path to a pre-written scenario JSON file"
    ),
    variant: str = typer.Option(
        "hardened", "--variant", help="Agent variant: naive | hardened | broken"
    ),
    save: bool = typer.Option(True, "--save/--no-save", help="Save transcript to logs/"),
) -> None:
    """Run a single test case through the sandbox and print/save the transcript."""

    if not test_id and not scenario_file:
        console.print("[red]Error:[/red] Provide either --test-id or --scenario-file.")
        raise typer.Exit(code=1)

    with tempfile.TemporaryDirectory() as tmp_dir:
        if test_id:
            console.print(f"[bold]Loading test case:[/bold] {test_id}")
            scenario = _load_scenario_by_id(test_id)
        else:
            console.print(f"[bold]Loading scenario file:[/bold] {scenario_file}")
            scenario = json.loads(scenario_file.read_text(encoding="utf-8"))
            test_id = scenario.get("id", "CUSTOM")

        scenario_path = _write_scenario_file(scenario, tmp_dir)

        console.print(
            Panel(
                f"[bold]Test:[/bold] {test_id}  [bold]Variant:[/bold] {variant}\n"
                f"[bold]Scenario:[/bold] {scenario.get('scenario', '—')[:120]}",
                title="Creuset Sandbox",
            )
        )

        transcript = _run_container(scenario_path, variant, test_id)

    status = transcript.get("status", "unknown")
    color = "green" if status == "completed" else "red"
    console.print(f"\n[{color}]Status:[/{color}] {status}")
    console.print(f"[dim]Tool calls:[/dim] {len(transcript.get('tool_calls', []))}")
    console.print(f"[dim]LLM calls:[/dim] {transcript.get('llm_calls_made', '?')}")
    console.print(f"[dim]Elapsed:[/dim] {transcript.get('elapsed_seconds', '?')}s")

    if save:
        out_path = _save_transcript(transcript, variant)
        console.print(f"\n[bold]Transcript saved:[/bold] {out_path}")

    # Print full transcript JSON for piping / gate consumption
    print(json.dumps(transcript, indent=2))

    if status not in ("completed",):
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
