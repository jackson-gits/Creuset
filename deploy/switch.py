"""
deploy/switch.py
─────────────────
Blue-green router state manager.

Reads and writes deploy/state.json to track which slot is active.
Called by:
  - gate/run_gate.py (on pass → switch to green)
  - monitor/watch.py (on anomaly → rollback to previous)

Usage:
  python deploy/switch.py status
  python deploy/switch.py switch green --version v1.2.3
  python deploy/switch.py rollback
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

app = typer.Typer(add_completion=False)
console = Console()

_ROOT = Path(__file__).parent.parent
_STATE_FILE = Path(__file__).parent / "state.json"
_GATE_LOGS = _ROOT / "logs" / "gate_runs"

_DEFAULT_STATE = {"active": "blue", "previous": None, "version": "initial", "switched_at": None}


# ── State helpers ─────────────────────────────────────────────────────────────

def _read_state() -> dict:
    if not _STATE_FILE.exists():
        return dict(_DEFAULT_STATE)
    return json.loads(_STATE_FILE.read_text())


def _write_state(state: dict) -> None:
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _STATE_FILE.write_text(json.dumps(state, indent=2))


def _log_switch(event: str, state: dict) -> None:
    """Append a switch event to the gate audit log."""
    _GATE_LOGS.mkdir(parents=True, exist_ok=True)
    ts = int(time.time())
    record = {"ts": ts, "event": event, "state": state}
    log_path = _GATE_LOGS / f"switch_{ts}.json"
    log_path.write_text(json.dumps(record, indent=2))


# ── Commands ──────────────────────────────────────────────────────────────────

@app.command()
def status() -> None:
    """Print current blue-green state."""
    state = _read_state()
    console.print(f"[bold]Active slot:[/bold]   [cyan]{state['active']}[/cyan]")
    console.print(f"[bold]Previous slot:[/bold] [dim]{state.get('previous', 'none')}[/dim]")
    console.print(f"[bold]Version:[/bold]       {state.get('version', '?')}")
    console.print(f"[bold]Switched at:[/bold]   {state.get('switched_at', 'never')}")


@app.command()
def switch(
    target: str = typer.Argument(..., help="Target slot: 'blue' or 'green'"),
    version: str = typer.Option("unknown", "--version", help="Version tag being activated"),
) -> None:
    """Switch active traffic to the specified slot."""
    if target not in ("blue", "green"):
        console.print("[red]Error:[/red] target must be 'blue' or 'green'.")
        raise typer.Exit(code=1)

    state = _read_state()
    previous = state["active"]

    if previous == target:
        console.print(f"[yellow]Already on {target}. No switch needed.[/yellow]")
        return

    new_state = {
        "active": target,
        "previous": previous,
        "version": version,
        "switched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    _write_state(new_state)
    _log_switch("switch", new_state)

    console.print(f"[green]✓ Switched:[/green] {previous} → {target} (version: {version})")


@app.command()
def rollback() -> None:
    """Roll back to the previous active slot."""
    state = _read_state()
    previous = state.get("previous")

    if not previous:
        console.print("[red]No previous slot recorded. Cannot roll back.[/red]")
        raise typer.Exit(code=1)

    new_state = {
        "active": previous,
        "previous": state["active"],
        "version": f"rollback-from-{state.get('version', '?')}",
        "switched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    _write_state(new_state)
    _log_switch("rollback", new_state)

    console.print(f"[bold yellow]⚠ Rollback:[/bold yellow] {state['active']} → {previous}")


if __name__ == "__main__":
    app()
