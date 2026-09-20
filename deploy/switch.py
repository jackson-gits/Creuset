"""
deploy/switch.py
─────────────────
Blue-green router state manager.

Reads and writes deploy/state/state.json to track which slot is active.
That directory is bind-mounted read-only into the router container, which
re-reads it on every request — so a switch takes effect without a restart.

Alongside it, each switch writes deploy/state/<slot>.env (AGENT_VARIANT,
AGENT_VERSION), which docker-compose feeds to that slot's container. The
env file is what makes a slot actually run the candidate build; recreate
the slot to pick it up:
    docker compose up -d --force-recreate agent-green

Called by:
  - gate/run_gate.py (on pass → switch to green)
  - monitor/watch.py (on anomaly → rollback to previous)

Usage:
  python deploy/switch.py status
  python deploy/switch.py switch green --version v1.2.3 --variant hardened
  python deploy/switch.py rollback
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

app = typer.Typer(add_completion=False)
# Windows consoles/pipes default to cp1252; force UTF-8 so rich output never crashes.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

console = Console()

_ROOT = Path(__file__).parent.parent
_STATE_DIR = Path(__file__).parent / "state"
_STATE_FILE = _STATE_DIR / "state.json"
_LEGACY_STATE_FILE = Path(__file__).parent / "state.json"  # pre-state-dir layout
_GATE_LOGS = _ROOT / "logs" / "gate_runs"

# `version`/`variant` describe the ACTIVE slot. `slots` records what each slot
# runs independently, which is what makes an honest rollback possible: without
# it, rolling back could only report the build it was rolling away from.
_DEFAULT_STATE = {"active": "blue", "previous": None, "version": "initial",
                  "variant": None, "switched_at": None,
                  "slots": {"blue": {"version": "initial", "variant": None},
                            "green": {"version": "unknown", "variant": None}}}


# ── State helpers ─────────────────────────────────────────────────────────────

def _read_state() -> dict:
    for path in (_STATE_FILE, _LEGACY_STATE_FILE):
        if path.exists():
            return _migrate(json.loads(path.read_text(encoding="utf-8")))
    return json.loads(json.dumps(_DEFAULT_STATE))  # deep copy


def _migrate(state: dict) -> dict:
    """
    Backfill `slots` for state files written before it existed.

    Only the active slot's build is knowable from an old file, so the other slot
    is marked unknown rather than guessed - claiming a build that was never
    recorded is exactly the kind of thing this field exists to prevent.
    """
    if "slots" in state:
        return state
    active = state.get("active", "blue")
    state["slots"] = {
        slot: ({"version": state.get("version", "unknown"), "variant": state.get("variant")}
               if slot == active else {"version": "unknown", "variant": None})
        for slot in ("blue", "green")
    }
    return state


def _write_state(state: dict) -> None:
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    _STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def _write_slot_env(slot: str, variant: Optional[str], version: str) -> None:
    """
    Record what a slot should run. docker-compose reads this as that slot's
    env_file, so the slot runs the gated build after `docker compose up -d
    --force-recreate agent-<slot>`.
    """
    if not variant:
        return
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    (_STATE_DIR / f"{slot}.env").write_text(
        f"AGENT_VARIANT={variant}\nAGENT_VERSION={version}\n", encoding="utf-8"
    )


def _log_switch(event: str, state: dict) -> None:
    """Append a switch event to the gate audit log."""
    _GATE_LOGS.mkdir(parents=True, exist_ok=True)
    ts = int(time.time())
    record = {"ts": ts, "event": event, "state": state}
    log_path = _GATE_LOGS / f"switch_{ts}.json"
    log_path.write_text(json.dumps(record, indent=2), encoding="utf-8")


# ── Commands ──────────────────────────────────────────────────────────────────

@app.command()
def status() -> None:
    """Print current blue-green state."""
    state = _read_state()
    console.print(f"[bold]Active slot:[/bold]   [cyan]{state['active']}[/cyan]")
    console.print(f"[bold]Previous slot:[/bold] [dim]{state.get('previous', 'none')}[/dim]")
    console.print(f"[bold]Version:[/bold]       {state.get('version', '?')}")
    console.print(f"[bold]Variant:[/bold]       {state.get('variant') or '?'}")
    console.print(f"[bold]Switched at:[/bold]   {state.get('switched_at', 'never')}")
    for slot, build in (state.get("slots") or {}).items():
        marker = "[cyan]<- live[/cyan]" if slot == state["active"] else ""
        console.print(f"  [dim]{slot}:[/dim] version={build.get('version', '?')} "
                      f"variant={build.get('variant') or '?'} {marker}")
    if state.get("rolled_back_from"):
        rb = state["rolled_back_from"]
        console.print(f"  [dim]rolled back from {rb.get('slot')} "
                      f"(version {rb.get('version')}, variant {rb.get('variant')})[/dim]")


@app.command()
def prepare(
    slot: str = typer.Argument(..., help="Slot to stage: 'blue' or 'green'"),
    version: str = typer.Option("unknown", "--version", help="Version tag being staged"),
    variant: str = typer.Option(..., "--variant", help="Agent variant the slot should run"),
) -> None:
    """
    Stage a build into a slot WITHOUT moving traffic: writes deploy/state/<slot>.env.

    The slot must then be recreated to pick it up (the gate does this before it
    switches traffic, so the slot is already running the gated build):
        docker compose up -d --force-recreate --wait agent-<slot>
    """
    if slot not in ("blue", "green"):
        console.print("[red]Error:[/red] slot must be 'blue' or 'green'.")
        raise typer.Exit(code=1)
    _write_slot_env(slot, variant, version)
    state = _read_state()
    state["slots"][slot] = {"version": version, "variant": variant}
    _write_state(state)
    console.print(f"[green]✓ Staged:[/green] {slot} → variant={variant} version={version}")


@app.command()
def switch(
    target: str = typer.Argument(..., help="Target slot: 'blue' or 'green'"),
    version: str = typer.Option("unknown", "--version", help="Version tag being activated"),
    variant: Optional[str] = typer.Option(None, "--variant", help="Agent variant the slot should run"),
) -> None:
    """Switch active traffic to the specified slot."""
    if target not in ("blue", "green"):
        console.print("[red]Error:[/red] target must be 'blue' or 'green'.")
        raise typer.Exit(code=1)

    state = _read_state()
    previous = state["active"]

    # The slot's env file is written even when the slot is already active:
    # it records which build was gated, not which slot serves traffic.
    _write_slot_env(target, variant, version)
    state["slots"][target] = {"version": version, "variant": variant or state.get("variant")}

    if previous == target:
        _write_state(state)  # keep the build record even when traffic does not move
        console.print(f"[yellow]Already on {target}. No switch needed.[/yellow]")
        return

    new_state = {
        "active": target,
        "previous": previous,
        "version": version,
        "variant": variant or state.get("variant"),
        "switched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "slots": state["slots"],
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

    # What is live after a rollback is whatever `previous` was already running.
    # Reporting `rollback-from-<old>` as the version, and carrying the abandoned
    # slot's variant across with it, described the build being rolled AWAY from
    # as though it were the one now serving traffic - the audit record then named
    # the wrong variant as live.
    restored = state["slots"].get(previous) or {"version": "unknown", "variant": None}
    new_state = {
        "active": previous,
        "previous": state["active"],
        "version": restored.get("version", "unknown"),
        "variant": restored.get("variant"),
        "switched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "rolled_back_from": {"slot": state["active"], "version": state.get("version"),
                             "variant": state.get("variant")},
        "slots": state["slots"],
    }
    _write_state(new_state)
    _log_switch("rollback", new_state)

    console.print(f"[bold yellow]⚠ Rollback:[/bold yellow] {state['active']} → {previous} "
                  f"(now serving version {new_state['version']}, variant {new_state['variant']})")


if __name__ == "__main__":
    app()
