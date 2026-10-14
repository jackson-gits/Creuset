"""
gate/run_gate.py
─────────────────
End-to-end deployment gate orchestrator.

Flow:
  1. Receive --version tag for the candidate agent build.
  2. Run the attack library against the candidate via the sandbox.
  3. Score all transcripts with the judge pipeline.
  4. If score clears all thresholds → stage the build in the INACTIVE slot,
     check that slot runs the exact image that was tested, then switch traffic.
  5. If score fails → block deployment; the live slot keeps serving.
  6. Fail-closed: sandbox crash, timeout, or unexpected error = gate FAIL.

Every gate run writes a timestamped record to logs/gate_runs/:
  - Version and subject tested (image ID included)
  - Full per-test results
  - Final verdict
  - Decision taken (deployed / blocked / dry run / deploy failed)

This is both the security audit trail and the evaluation dataset.

Exit codes (stable; CI depends on them):
  0  PASS: deployed, or would deploy (--dry-run)
  1  FAIL: blocked by the gate, or the suite/scorer failed (fail-closed)
  2  rejected before anything ran (bad version/variant/image, bad flags)
  3  PASS, but the deploy did not complete: the gated build is NOT live

Usage:
  python gate/run_gate.py --version v1.2.3
  python gate/run_gate.py --version naive --variant naive
  python gate/run_gate.py --version hardened --variant hardened --skip-model-judge
  python gate/run_gate.py --version 1.4.0 --variant v1-4 --agent-image my-agent:1.4.0 \\
      --library my_cases.yaml --dry-run
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule

_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_ROOT / ".env")

app = typer.Typer(add_completion=False)
# Windows consoles/pipes default to cp1252; force UTF-8 so rich output never crashes.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

console = Console()

_ATTACK_LIB = _ROOT / "attacks" / "attack_library.yaml"
_RUNS_DIR = _ROOT / "logs" / "runs"
_GATE_LOGS = _ROOT / "logs" / "gate_runs"
_SCORE_SCRIPT = _ROOT / "judge" / "score.py"
_LOADER_SCRIPT = _ROOT / "attacks" / "loader.py"
_SWITCH_SCRIPT = _ROOT / "deploy" / "switch.py"

EXIT_PASS, EXIT_BLOCKED, EXIT_REJECTED, EXIT_DEPLOY_FAILED = 0, 1, 2, 3

sys.path.insert(0, str(_ROOT / "deploy"))
sys.path.insert(0, str(_ROOT / "sandbox"))
sys.path.insert(0, str(_ROOT / "judge"))
from model_judge import JudgeConfigError, check_config  # noqa: E402
from run_test import AGENT_IMAGE, image_id, parse_agent_env, subject_problem  # noqa: E402
from switch import StateError, inactive_slot, load_state, validate_build  # noqa: E402


# ── Helpers ───────────────────────────────────────────────────────────────────

def _newest_manifest(since: float) -> Optional[Path]:
    """
    Newest batch manifest written by attacks/loader.py after `since`.
    The time bound matters: scoring a manifest from an earlier run would
    silently grade stale transcripts.
    """
    manifests = [p for p in _RUNS_DIR.glob("*/manifest.json") if p.stat().st_mtime >= since]
    return max(manifests, key=lambda p: p.stat().st_mtime, default=None)


def _run_attack_suite(variant: str, library: Optional[Path] = None,
                      agent_image: Optional[str] = None,
                      extra_args: Sequence[str] = ()) -> Optional[Path]:
    """
    Run the attack library through the sandbox (calls loader.py).
    Returns the path to the batch manifest, or None on failure.
    """
    console.print(Rule("Phase 1 — Running attack suite"))
    cmd = [
        sys.executable, str(_LOADER_SCRIPT),
        "--variant", variant,
    ]
    if library:
        cmd += ["--library", str(library)]
    if agent_image:
        cmd += ["--agent-image", agent_image]
    cmd += list(extra_args)
    console.print(f"[dim]{' '.join(cmd)}[/dim]")

    started = time.time()
    result = subprocess.run(cmd, cwd=str(_ROOT), capture_output=False, text=True)

    if result.returncode != 0:
        console.print("[red]✗ Attack suite runner failed (non-zero exit).[/red]")
        return None

    manifest = _newest_manifest(started)
    if manifest is None:
        console.print("[red]✗ No batch manifest found after loader run.[/red]")
        return None

    return manifest


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

    # score.py puts its own directory on sys.path, so it runs from anywhere.
    # Its exit code is 1 for an ordinary gate FAIL, so the report file — not the
    # exit code — is what says whether scoring happened.
    subprocess.run(cmd, cwd=str(_ROOT), capture_output=False, text=True)

    if not report_path.exists():
        console.print("[red]✗ Score report not written. Treating as gate FAIL.[/red]")
        return None

    return json.loads(report_path.read_text(encoding="utf-8"))


def tested_image_id(manifest_path: Optional[Path]) -> Optional[str]:
    """
    The one image ID every case in the batch ran, or None if the batch does not
    record it or ran more than one (a resumed batch that mixed builds).
    """
    if manifest_path is None:
        return None
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    ids = {e.get("agent_image_id") for e in manifest.get("cases", [])}
    ids.add((manifest.get("subject") or {}).get("image_id"))
    return ids.pop() if len(ids) == 1 else None


def _write_gate_record(
    version: str,
    variant: str,
    score_report: Optional[Dict[str, Any]],
    verdict: str,
    decision: str,
    error: Optional[str] = None,
    **extra: Any,
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
        **extra,
        "score_report": score_report,
    }
    path = _GATE_LOGS / f"gate_{ts}.json"
    path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return path


def _judge_problem(skip_model_judge: bool) -> Optional[str]:
    """
    Why the LLM judge could not be called as configured, or None. Asked before
    the suite: otherwise a missing JUDGE_MODEL or a key that may not go to
    JUDGE_API_BASE surfaces only after the agent quota is spent, as every case
    failing closed.
    """
    if skip_model_judge:
        return None
    try:
        check_config()
    except JudgeConfigError as e:
        return f"LLM judge misconfigured: {e} (or pass --skip-model-judge)"
    return None


# ── Deploy ────────────────────────────────────────────────────────────────────

def _stage_slot(slot: str, version: str, variant: str) -> Optional[str]:
    """
    Put the gated build into `slot` BEFORE any traffic moves: write the slot's
    env file, then recreate the container so it actually runs that build and
    passes its healthcheck. Returns why it failed, or None.
    """
    console.print(Rule(f"Phase 3 — Staging the {slot} slot"))
    staged = subprocess.run(
        [sys.executable, str(_SWITCH_SCRIPT), "prepare", slot,
         "--version", version, "--variant", variant],
        cwd=str(_ROOT), capture_output=False, text=True,
    )
    if staged.returncode != 0:
        return f"could not write the {slot} slot's build (switch.py prepare exited {staged.returncode})"

    recreate = subprocess.run(
        ["docker", "compose", "up", "-d", "--force-recreate", "--wait", f"agent-{slot}"],
        cwd=str(_ROOT), capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if recreate.returncode != 0:
        return f"the {slot} slot did not come up healthy: {recreate.stderr.strip()[-400:]}"
    return None


def _slot_image_id(slot: str) -> Optional[str]:
    """The image ID the slot's running container was created from."""
    ps = subprocess.run(["docker", "compose", "ps", "-q", f"agent-{slot}"], cwd=str(_ROOT),
                        capture_output=True, text=True, encoding="utf-8", errors="replace")
    container = ps.stdout.strip()
    if ps.returncode != 0 or not container:
        return None
    inspect = subprocess.run(["docker", "inspect", container, "--format", "{{.Image}}"],
                             capture_output=True, text=True, encoding="utf-8", errors="replace")
    if inspect.returncode != 0:
        return None
    return inspect.stdout.strip() or None


def _do_switch(slot: str, version: str, variant: str) -> bool:
    """Call deploy/switch.py to move traffic to `slot`. Returns True on success."""
    cmd = [sys.executable, str(_SWITCH_SCRIPT), "switch", slot,
           "--version", version, "--variant", variant]
    result = subprocess.run(cmd, cwd=str(_ROOT), capture_output=False, text=True)
    return result.returncode == 0


def _deploy(version: str, variant: str, tested: Optional[str]) -> Dict[str, Any]:
    """
    Stage the gated build in the inactive slot and move traffic to it.

    Returns {"ok", "slot", "error"}. Traffic moves only once the slot is
    running the very image the suite tested: the tag the slot is built from can
    be re-pointed (a rebuild during a 30-minute gate run), and deploying
    "creuset-agent:latest" would then put untested bytes live under a PASS.
    """
    try:
        slot = inactive_slot(load_state())
    except StateError as e:
        return {"ok": False, "slot": None, "error": f"deploy state unreadable: {e}"}

    if tested is None:
        return {"ok": False, "slot": slot,
                "error": "the batch does not record a single image ID for what it tested"}
    current = image_id(AGENT_IMAGE)
    if current != tested:
        return {"ok": False, "slot": slot,
                "error": f"{AGENT_IMAGE} is now {current or 'missing'}, but the gate tested {tested}: "
                         f"it was rebuilt during the run. Re-run the gate on the new build."}

    problem = _stage_slot(slot, version, variant)
    if problem:
        return {"ok": False, "slot": slot, "error": problem}
    running = _slot_image_id(slot)
    if running != tested:
        return {"ok": False, "slot": slot,
                "error": f"the {slot} slot runs {running or 'nothing'}, not the tested image {tested}"}
    console.print(f"[green]✓ {slot} slot is running the gated image {tested[:19]}.[/green]")

    if not _do_switch(slot, version, variant):
        return {"ok": False, "slot": slot, "error": f"switch.py could not move traffic to {slot}"}
    return {"ok": True, "slot": slot, "error": None}


# ── CLI ───────────────────────────────────────────────────────────────────────

@app.command()
def main(
    version: str = typer.Option(..., "--version", help="Version tag for the candidate agent (e.g. v1.2.3 or 'naive')."),
    variant: Optional[str] = typer.Option(None, "--variant", help="Agent variant override. Defaults to --version."),
    skip_model_judge: bool = typer.Option(False, "--skip-model-judge", help="Only run rule-based checks (faster, no LLM cost)."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Score but don't actually switch slots."),
    library: Optional[Path] = typer.Option(None, "--library", help="Test library (default: attacks/attack_library.yaml)."),
    agent_image: Optional[str] = typer.Option(None, "--agent-image", envvar="CREUSET_AGENT_IMAGE",
                                              help="Gate this image instead of the bundled agent. Requires --dry-run: "
                                                   "the blue/green slots run the bundled agent only."),
    agent_env: Optional[List[str]] = typer.Option(None, "--agent-env", metavar="KEY=VALUE",
                                                  help="A setting for the agent's container (repeatable). Never a secret."),
    agent_env_file: Optional[Path] = typer.Option(None, "--agent-env-file", envvar="CREUSET_AGENT_ENV_FILE",
                                                  help="KEY=VALUE lines for the agent's container. Never secrets."),
) -> None:
    """
    Run the full Creuset deployment gate.

    Tests the candidate agent version, scores results, and flips the
    blue-green router only if all safety thresholds are met.
    """
    _variant = variant or version
    start_ts = time.time()

    # Checked before the suite, not after: switch.py would refuse a bad value
    # anyway, but only once a 30-minute run had spent its quota.
    problem = (validate_build(version, _variant, require_variant_file=not agent_image)
               or subject_problem(_variant, agent_image))
    if not problem and agent_image and not dry_run:
        problem = ("--agent-image needs --dry-run: the blue/green slots run the bundled agent, so the "
                   "gate can give a verdict on another image but cannot deploy it")
    if not problem and library is not None and not library.is_file():
        problem = f"library {library} does not exist"
    if not problem:
        try:
            parse_agent_env(agent_env or (), agent_env_file)
        except (OSError, ValueError) as e:
            problem = f"agent settings: {e}"
    problem = problem or _judge_problem(skip_model_judge)
    if problem:
        record = _write_gate_record(version, _variant, None, "FAIL", "BLOCKED",
                                    error=f"Rejected before running: {problem}")
        console.print(f"[bold red]⛔ GATE BLOCKED[/bold red] — {problem}. Audit: {record}")
        raise typer.Exit(code=EXIT_REJECTED)

    console.print(
        Panel(
            f"[bold]Version:[/bold] {version}  [bold]Variant:[/bold] {_variant}  "
            f"[bold]Dry run:[/bold] {dry_run}"
            + (f"\n[bold]Image:[/bold] {agent_image}" if agent_image else "")
            + (f"\n[bold]Library:[/bold] {library}" if library else ""),
            title="[bold cyan]Creuset Deployment Gate[/bold cyan]",
        )
    )

    # ── Step 1: Run attack suite ──────────────────────────────────────────────
    suite_args: List[str] = [arg for pair in (agent_env or ()) for arg in ("--agent-env", pair)]
    if agent_env_file:
        suite_args += ["--agent-env-file", str(agent_env_file)]
    manifest = _run_attack_suite(_variant, library, agent_image, suite_args)

    if manifest is None:
        # Fail-closed: sandbox runner failure = gate FAIL
        record = _write_gate_record(
            version, _variant, None, "FAIL", "BLOCKED",
            error="Attack suite runner failed or produced no manifest.",
        )
        console.print(f"\n[bold red]⛔ GATE BLOCKED[/bold red] — sandbox failure. Audit: {record}")
        raise typer.Exit(code=EXIT_BLOCKED)

    console.print(f"[green]✓ Batch manifest:[/green] {manifest}")
    tested = tested_image_id(manifest)

    # ── Step 2: Score ─────────────────────────────────────────────────────────
    score_report = _run_scorer(manifest, skip_model_judge)

    if score_report is None:
        record = _write_gate_record(
            version, _variant, None, "FAIL", "BLOCKED",
            error="Scorer failed or produced no report.", manifest=str(manifest),
        )
        console.print(f"\n[bold red]⛔ GATE BLOCKED[/bold red] — scorer failure. Audit: {record}")
        raise typer.Exit(code=EXIT_BLOCKED)

    gate_verdict = score_report.get("gate_verdict", "FAIL")
    note: Optional[str] = None
    # A PASS is only deployable if it is also a measurement. Every cause of
    # `valid: false` should already have failed its own case, but this is the
    # last line before live traffic moves, so it does not rely on that.
    if gate_verdict == "PASS" and score_report.get("valid") is not True:
        console.print("[bold red]Score report passed but is not a valid measurement "
                      "(valid != true) — treating as FAIL.[/bold red]")
        gate_verdict = "FAIL"
        note = "Score report passed but was not a valid measurement; blocked (fail-closed)."
    elapsed = round(time.time() - start_ts, 1)

    console.print(Rule("Gate Decision"))
    console.print(f"[bold]Gate verdict:[/bold] [{'green' if gate_verdict == 'PASS' else 'red'}]{gate_verdict}[/]")
    console.print(f"[dim]Elapsed: {elapsed}s[/dim]")

    # ── Step 3: Switch or block ───────────────────────────────────────────────
    slot: Optional[str] = None
    if gate_verdict == "PASS":
        if dry_run:
            decision = "DRY_RUN_WOULD_DEPLOY"
            exit_code = EXIT_PASS
            console.print("[bold yellow]⚡ Dry run — would deploy. Skipping the switch.[/bold yellow]")
        else:
            outcome = _deploy(version, _variant, tested)
            slot = outcome["slot"]
            if outcome["ok"]:
                decision, exit_code = "DEPLOYED", EXIT_PASS
                console.print(f"\n[bold green]✅ DEPLOYED[/bold green] — version [cyan]{version}[/cyan] "
                              f"is now live ({slot} slot).")
            else:
                # Not 0: a pipeline that reads the exit code must not believe the
                # gated build is live when it is not.
                decision, exit_code = "SWITCH_FAILED", EXIT_DEPLOY_FAILED
                note = f"Gate passed but the deploy did not complete: {outcome['error']}"
                console.print(f"\n[bold red]⛔ Deploy failed[/bold red] — {outcome['error']}. "
                              f"Traffic did not move; manual intervention required.")
    else:
        decision, exit_code = "BLOCKED", EXIT_BLOCKED
        console.print(f"\n[bold red]⛔ GATE BLOCKED[/bold red] — version [cyan]{version}[/cyan] failed safety gate. "
                      f"The live slot keeps serving.")

    # ── Audit record ──────────────────────────────────────────────────────────
    record_path = _write_gate_record(
        version, _variant, score_report, gate_verdict, decision, error=note,
        manifest=str(manifest), tested_image_id=tested, slot=slot,
        library=str((library or _ATTACK_LIB).resolve()),
        agent_image=agent_image or AGENT_IMAGE,
    )
    console.print(f"\n[bold]Audit record:[/bold] {record_path}")

    raise typer.Exit(code=exit_code)


if __name__ == "__main__":
    app()
