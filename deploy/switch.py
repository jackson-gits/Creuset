"""
deploy/switch.py
─────────────────
Blue-green router state manager.

Reads and writes <state dir>/state.json to track which slot is active. The
state dir is deploy/state unless CREUSET_STATE_DIR points somewhere else.
deploy/state is bind-mounted read-only into the router container, which
re-reads it on every request — so a switch takes effect without a restart.

Alongside it, each switch writes <state dir>/<slot>.env (AGENT_VARIANT,
AGENT_VERSION), which docker-compose feeds to that slot's container. The
env file is what makes a slot actually run the candidate build; recreate
the slot to pick it up:
    docker compose up -d --force-recreate agent-green

Compose and the router container only ever read deploy/state, so pointing
CREUSET_STATE_DIR elsewhere detaches this script from the running stack —
which is what a demo or a test wants: it can switch and roll back without
moving real traffic.

Every read-modify-write holds <state dir>/.switch.lock, so the gate staging a
build and the monitor rolling one back cannot interleave and lose an update.

Called by:
  - gate/run_gate.py (on pass → stage the build, then switch traffic to it)
  - monitor/watch.py (on anomaly → rollback to previous)

Usage:
  python deploy/switch.py status
  python deploy/switch.py prepare green --version v1.2.3 --variant hardened
  python deploy/switch.py switch green --version v1.2.3 --variant hardened
  python deploy/switch.py rollback [--expect-active green]
"""

from __future__ import annotations

import copy
import json
import os
import re
import sys
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator, Mapping, NoReturn, Optional

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

SLOTS = ("blue", "green")

_ROOT = Path(__file__).parent.parent
_DEFAULT_STATE_DIR = Path(__file__).parent / "state"


def _state_dir_from(env: Mapping[str, str]) -> Path:
    """
    CREUSET_STATE_DIR, or deploy/state. A relative value is anchored at the repo
    root rather than the cwd: the gate and the monitor run this script with
    cwd=<repo root>, so resolving against the caller's cwd would let a process
    and its own switch.py subprocess read two different state files.
    """
    configured = (env.get("CREUSET_STATE_DIR") or "").strip()
    return _ROOT / configured if configured else _DEFAULT_STATE_DIR


# Every function reads these module attributes at call time; they are the one
# place a path is decided (the tests point them at a tmp dir).
_STATE_DIR = _state_dir_from(os.environ)
_STATE_FILE = _STATE_DIR / "state.json"
# Pre-state-dir layout. Only consulted for the default dir: a throwaway state
# dir must never inherit a real deployment's state through the legacy file.
_LEGACY_STATE_FILE: Optional[Path] = (
    None if _STATE_DIR != _DEFAULT_STATE_DIR else Path(__file__).parent / "state.json")
_GATE_LOGS = _ROOT / "logs" / "gate_runs"
_VARIANTS_DIR = _ROOT / "agent" / "variants"

# Both values are written into deploy/state/<slot>.env, which Compose loads as
# the slot container's environment. Unvalidated, a version of "v1\nPYTHONPATH=…"
# would set arbitrary variables inside the agent, and "$X" would be interpolated
# by Compose — so only a conservative tag/SHA alphabet is accepted.
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+/-]{0,127}$")
VARIANT_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

# `version`/`variant` describe the ACTIVE slot. `slots` records what each slot
# runs independently, which is what makes an honest rollback possible: without
# it, rolling back could only report the build it was rolling away from.
_DEFAULT_STATE = {"active": "blue", "previous": None, "version": "initial",
                  "variant": None, "switched_at": None,
                  "slots": {"blue": {"version": "initial", "variant": None},
                            "green": {"version": "unknown", "variant": None}}}

_LOCK_NAME = ".switch.lock"
# A holder only reads and rewrites two small files, so it holds the lock for
# milliseconds. One this old was left by a process that died mid-update.
_LOCK_STALE_SECONDS = 30.0
# Longer than the stale age on purpose: a waiter then outlives a dead holder and
# breaks its lock rather than giving up. The monitor's rollback is one of the
# waiters, and a rollback refused over a lock nobody holds leaves a bad build live.
_LOCK_TIMEOUT_SECONDS = 40.0
_LOCK_POLL_SECONDS = 0.05


class StateError(Exception):
    """state.json exists but cannot say which slot is live."""


class LockTimeout(Exception):
    """Another process held the state lock for longer than we would wait."""


# ── State helpers ─────────────────────────────────────────────────────────────

def load_state() -> dict:
    """
    The deploy state, migrated to the current layout.

    A missing file is a fresh install: blue live, nothing staged. A file that
    exists but cannot be parsed, or names no known active slot, raises
    StateError — the router already refuses to route on such a file (503), and
    a switch or rollback that guessed instead would write its guess back as fact.
    """
    for path in (_STATE_FILE, _LEGACY_STATE_FILE):
        if path is None or not path.exists():
            continue
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise StateError(f"{path} is unreadable ({type(e).__name__}); "
                             f"fix or remove it - refusing to guess which slot is live") from e
        # A missing `active` is blue for the router too; agreeing with it matters
        # more than strictness, since the router is what actually serves traffic.
        if (not isinstance(state, dict) or state.get("active", "blue") not in SLOTS
                or not isinstance(state.get("slots", {}), dict)):
            raise StateError(f"{path} names no known active slot; "
                             f"refusing to guess which slot is live")
        state.setdefault("active", "blue")
        return _migrate(state)
    return copy.deepcopy(_DEFAULT_STATE)


def inactive_slot(state: dict) -> str:
    """
    The slot NOT serving traffic: where the next build belongs.

    Staging into the active slot recreates the container serving live traffic
    (an outage, and a dead slot if the candidate fails its healthcheck) and
    leaves `previous` pointing at a build two deploys old.
    """
    active = state.get("active", "blue")
    if active not in SLOTS:
        raise StateError(f"state names no known active slot: {active!r}")
    return "green" if active == "blue" else "blue"


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
        for slot in SLOTS
    }
    return state


def validate_build(version: str, variant: Optional[str],
                   require_variant_file: bool = True) -> Optional[str]:
    """
    Why (version, variant) cannot be staged, or None if it can.

    `require_variant_file=False` is for a subject that is not built from this
    repo (an external image): its variant is still a label written into files,
    so the alphabet is still enforced, but there is no agent/variants/<v>.txt
    for it to match.
    """
    if not VERSION_RE.fullmatch(version or ""):
        return (f"invalid version {version!r}: 1-128 chars of letters, digits and . _ + / -, "
                f"starting with a letter or digit")
    if variant is not None:
        if not VARIANT_RE.fullmatch(variant):
            return f"invalid variant {variant!r}: letters, digits, '-' and '_' only"
        # Staging a variant the image cannot load would bring the slot up only
        # to fail every request; refuse here instead.
        if require_variant_file and not (_VARIANTS_DIR / f"{variant}.txt").is_file():
            return f"unknown variant {variant!r}: no agent/variants/{variant}.txt"
    return None


def _retry_sharing_violation(op: Callable[[], None]) -> None:
    """
    Run a rename or unlink, retrying briefly on PermissionError. On Windows these
    fail while another process (Docker Desktop's file sharing, an editor) briefly
    holds the file open; that clears quickly.
    """
    for attempt in range(10):
        try:
            op()
            return
        except PermissionError:
            if attempt == 9:
                raise
            time.sleep(0.05)


def _atomic_write(path: Path, text: str) -> None:
    """
    Write via a temp file and rename. The router re-reads state.json on every
    request; a plain write_text can be observed half-written, and a router that
    cannot parse the file must not guess which slot is live.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(text, encoding="utf-8")
    try:
        _retry_sharing_violation(lambda: os.replace(tmp, path))
    except PermissionError:
        tmp.unlink(missing_ok=True)
        raise


def _write_state(state: dict) -> None:
    _atomic_write(_STATE_FILE, json.dumps(state, indent=2))


def _write_slot_env(slot: str, variant: Optional[str], version: str) -> None:
    """
    Record what a slot should run. docker-compose reads this as that slot's
    env_file, so the slot runs the gated build after `docker compose up -d
    --force-recreate agent-<slot>`.
    """
    if not variant:
        return
    problem = validate_build(version, variant)
    if problem:  # defence in depth: the commands check first, this is the sink
        raise ValueError(problem)
    _atomic_write(_STATE_DIR / f"{slot}.env", f"AGENT_VARIANT={variant}\nAGENT_VERSION={version}\n")


def _require_valid(version: str, variant: Optional[str]) -> None:
    problem = validate_build(version, variant)
    if problem:
        _fail(problem)


def _fail(message: str) -> NoReturn:
    console.print(f"[red]Error:[/red] {message}")
    raise typer.Exit(code=1)


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _log_switch(event: str, state: dict) -> Path:
    """
    Write one switch event to the gate audit log.

    Named to the millisecond plus a random suffix: second-resolution names let
    two events in the same second overwrite each other (8 switch events once
    left 4 files), and the audit trail silently lost rollbacks. Opened with
    O_EXCL ("x") as well, so a record can never replace another one.
    """
    _GATE_LOGS.mkdir(parents=True, exist_ok=True)
    now = time.time()
    ts_ms = int(now * 1000)
    event_id = f"{ts_ms}_{uuid.uuid4().hex[:8]}"
    record = {"ts": int(now), "ts_ms": ts_ms, "id": event_id, "event": event, "state": state}
    if _STATE_DIR != _DEFAULT_STATE_DIR:
        # A demo's switch never moved real traffic; say so, or its record is
        # indistinguishable from a real deploy's in the same log directory.
        record["state_dir"] = str(_STATE_DIR)
    path = _GATE_LOGS / f"switch_{event_id}.json"
    with open(path, "x", encoding="utf-8") as f:
        f.write(json.dumps(record, indent=2))
    return path


# ── Lock ──────────────────────────────────────────────────────────────────────

def _try_create(path: Path) -> bool:
    """Create `path` exclusively; False if it already exists."""
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        return False
    except PermissionError:
        # Windows reports a file still being deleted (the previous holder's
        # release, in flight) as access denied rather than as existing.
        if os.name == "nt":
            return False
        raise
    try:
        os.write(fd, f"pid {os.getpid()}\n".encode())
    finally:
        os.close(fd)
    return True


def _age(path: Path) -> Optional[float]:
    """Seconds since `path` was written, or None if it is gone (or going)."""
    try:
        return time.time() - path.stat().st_mtime
    except OSError:
        return None


def _holder(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip() or "unknown holder"
    except OSError:
        return "unknown holder"


def _unlink(path: Path) -> None:
    _retry_sharing_violation(lambda: path.unlink(missing_ok=True))


def _break_if_stale(lock: Path) -> bool:
    """Remove `lock` if its holder evidently died. True if it was removed."""
    age = _age(lock)
    if age is None or age < _LOCK_STALE_SECONDS:
        return False
    # Two waiters can both see the same dead lock. Breaking it under a second
    # lock, and re-checking its age there, stops the slower one from deleting
    # the fresh lock the faster one has just taken - two writers at once.
    breaker = lock.with_name(lock.name + ".break")
    if not _try_create(breaker):
        breaker_age = _age(breaker)  # only this old if a process died mid-break
        if breaker_age is not None and breaker_age >= _LOCK_STALE_SECONDS:
            _unlink(breaker)
        return False
    try:
        age = _age(lock)
        if age is None or age < _LOCK_STALE_SECONDS:
            return False
        console.print(f"[yellow]Breaking a stale state lock ({_holder(lock)}, {age:.0f}s old): "
                      f"its holder evidently died mid-update.[/yellow]")
        _unlink(lock)
        return True
    finally:
        _unlink(breaker)


@contextmanager
def state_lock(timeout: Optional[float] = None) -> Iterator[None]:
    """
    Hold <state dir>/.switch.lock for one read-modify-write of the state.

    Without it the gate's prepare/switch and the monitor's rollback each read
    state.json, change their part and write the whole file back, and the
    slower writer silently discards the other's update. O_CREAT|O_EXCL is
    atomic on POSIX and Windows alike, so this needs neither fcntl nor msvcrt.
    """
    lock = _STATE_DIR / _LOCK_NAME
    lock.parent.mkdir(parents=True, exist_ok=True)
    timeout = _LOCK_TIMEOUT_SECONDS if timeout is None else timeout
    deadline = time.monotonic() + timeout
    while not _try_create(lock):
        if _break_if_stale(lock):
            continue
        if time.monotonic() >= deadline:
            if _age(lock) is None:  # nobody holds it, yet we could not create it
                raise LockTimeout(f"could not create state lock {lock} in {timeout:.0f}s; "
                                  f"is the state dir writable?")
            raise LockTimeout(
                f"state lock {lock} is held ({_holder(lock)}); gave up after {timeout:.0f}s. "
                f"A lock older than {_LOCK_STALE_SECONDS:.0f}s is broken automatically.")
        time.sleep(_LOCK_POLL_SECONDS)
    try:
        yield
    finally:
        # Best effort: failing to remove our own lock must not mask the
        # command's outcome, and a lock left behind is broken once stale.
        try:
            _unlink(lock)
        except OSError as e:
            console.print(f"[yellow]Could not release {lock}: {type(e).__name__}[/yellow]")


@contextmanager
def _transaction() -> Iterator[dict]:
    """The locked state for one command; a lock or state failure exits 1."""
    try:
        with state_lock():
            yield load_state()
    except (StateError, LockTimeout, OSError) as e:
        _fail(str(e) if not isinstance(e, OSError) else f"{type(e).__name__}: {e}")


# ── Commands ──────────────────────────────────────────────────────────────────

@app.command()
def status() -> None:
    """Print current blue-green state."""
    try:
        state = load_state()
    except StateError as e:
        _fail(str(e))
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
    if slot not in SLOTS:
        _fail("slot must be 'blue' or 'green'.")
    _require_valid(version, variant)
    with _transaction() as state:
        if slot == state["active"]:
            console.print(f"[yellow]Note:[/yellow] {slot} is the live slot; recreating it to pick "
                          f"this up interrupts live traffic. The inactive slot is "
                          f"{inactive_slot(state)}.")
        _write_slot_env(slot, variant, version)
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
    if target not in SLOTS:
        _fail("target must be 'blue' or 'green'.")
    _require_valid(version, variant)

    with _transaction() as state:
        previous = state["active"]

        # The slot's env file is written even when the slot is already active:
        # it records which build was gated, not which slot serves traffic.
        _write_slot_env(target, variant, version)
        # Without --variant the slot keeps the variant it was staged with: its
        # env file was not rewritten, so that is what the container runs. The
        # top-level variant belongs to the slot traffic is moving AWAY from.
        slot_variant = variant or (state["slots"].get(target) or {}).get("variant")
        state["slots"][target] = {"version": version, "variant": slot_variant}

        if previous == target:
            # Traffic does not move, but the live slot's build just changed.
            # Leaving the top-level record alone kept naming the old build as
            # live: "Already on green" with version v1 while green served v2.
            state["version"] = version
            state["variant"] = slot_variant
            _write_state(state)
            _log_switch("redeploy", state)
            console.print(f"[yellow]Already on {target}. No switch needed; "
                          f"recorded version {version} as its live build.[/yellow]")
            return

        new_state = {
            "active": target,
            "previous": previous,
            "version": version,
            "variant": slot_variant,
            "switched_at": _now_iso(),
            "slots": state["slots"],
        }
        _write_state(new_state)
        _log_switch("switch", new_state)

    console.print(f"[green]✓ Switched:[/green] {previous} → {target} (version: {version})")


@app.command()
def rollback(
    expect_active: Optional[str] = typer.Option(
        None, "--expect-active", metavar="SLOT",
        help="Roll back only if SLOT is the live slot; otherwise change nothing and exit 0. "
             "Makes a repeated rollback (a second anomaly, a restarted monitor) a no-op "
             "instead of toggling traffic back to the build just rolled away from."),
) -> None:
    """Roll back to the previous active slot."""
    if expect_active is not None and expect_active not in SLOTS:
        _fail("--expect-active must be 'blue' or 'green'.")

    with _transaction() as state:
        active = state["active"]
        if expect_active is not None and active != expect_active:
            console.print(f"[yellow]Active slot is {active}, not {expect_active}: "
                          f"nothing to roll back. No change made.[/yellow]")
            return
        previous = state.get("previous")
        if previous not in SLOTS or previous == active:
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
            "previous": active,
            "version": restored.get("version", "unknown"),
            "variant": restored.get("variant"),
            "switched_at": _now_iso(),
            "rolled_back_from": {"slot": active, "version": state.get("version"),
                                 "variant": state.get("variant")},
            "slots": state["slots"],
        }
        _write_state(new_state)
        _log_switch("rollback", new_state)

    console.print(f"[bold yellow]⚠ Rollback:[/bold yellow] {active} → {previous} "
                  f"(now serving version {new_state['version']}, variant {new_state['variant']})")


if __name__ == "__main__":
    app()
