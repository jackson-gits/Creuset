"""
sandbox/run_test.py
────────────────────
Per-test harness: runs ONE test case in a fresh, locked-down agent container,
captures the transcript, and guarantees the container is gone afterwards.

Each test container:
  docker run --rm --name creuset-test-<run_id>
    --network creuset-net            # internal: true — no internet
    --read-only --tmpfs /tmp         # immutable filesystem
    --cap-drop ALL --security-opt no-new-privileges --pids-limit 256
    --memory 512m --cpus 1.0
    -e ... (explicit allowlist; the real LLM key is NOT passed — llm-proxy injects it)
    -v <scenario.json>:/scenario.json:ro
    creuset-agent:latest --scenario-file /scenario.json --variant <variant>

On timeout the container is force-removed (killing the docker CLI alone would
leave it running). Any failure produces a transcript with a non-"completed"
status, which the judge treats as FAIL (fail-closed).

Usage:
  python sandbox/run_test.py --test-id PI-001 --variant naive
  python sandbox/run_test.py --test-id BN-005 --variant hardened
  python sandbox/run_test.py --scenario-file my_case.json --variant hardened
  python sandbox/run_test.py --check          # preflight + isolation probe only
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

import typer
import yaml
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel


# Windows consoles/pipes default to cp1252; force UTF-8 so rich output never crashes.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_ROOT / ".env")

app = typer.Typer(add_completion=False)
console = Console(stderr=True)

# ── Configuration ─────────────────────────────────────────────────────────────
LIBRARIES = [_ROOT / "attacks" / "attack_library.yaml", _ROOT / "attacks" / "benign_tasks.yaml"]
_LOGS_DIR = _ROOT / "logs"
NETWORK = "creuset-net"
AGENT_IMAGE = os.getenv("AGENT_IMAGE_TAG", "creuset-agent:latest")
TIMEOUT = int(os.getenv("SANDBOX_TIMEOUT_SECONDS", "180"))
INFRA_CONTAINERS = ("llm-proxy", "mock-services")

# The ONLY environment a test container receives.
def _container_env(run_id: str) -> Dict[str, str]:
    return {
        "OPENAI_API_BASE": os.getenv("AGENT_API_BASE", "http://llm-proxy:11434/openai/v1"),
        "OPENAI_API_KEY": "sandbox-placeholder-key",  # real key injected by llm-proxy
        "AGENT_MODEL": os.getenv("AGENT_MODEL", "gpt-4o-mini"),
        "MOCK_SERVICES_HOST": "mock-services",
        "MOCK_SERVICES_PORT": "8001",
        "MAX_LLM_CALLS": os.getenv("MAX_LLM_CALLS", "15"),
        "LLM_MAX_RETRIES": os.getenv("LLM_MAX_RETRIES", "8"),
        "AGENT_MAX_TOKENS": os.getenv("AGENT_MAX_TOKENS", "700"),
        # Separate from AGENT_MAX_TOKENS on purpose: the empty-answer finalizer
        # needs room for a whole answer, not one step of a tool-calling loop.
        "FINALIZER_MAX_TOKENS": os.getenv("FINALIZER_MAX_TOKENS", "1024"),
        "CREUSET_RUN_ID": run_id,
    }


_SANDBOX_FLAGS = [
    "--network", NETWORK,
    "--read-only", "--tmpfs", "/tmp",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--pids-limit", "256",
    "--memory", "512m",
    "--cpus", "1.0",
    "--no-healthcheck",
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _docker(args: List[str], timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout,
        encoding="utf-8", errors="replace",
    )


def load_cases(path: Path) -> List[Dict[str, Any]]:
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    return raw if isinstance(raw, list) else raw.get("cases", [])


def find_case(test_id: str) -> Dict[str, Any]:
    """Look a case up by id in the attack library and the benign task set."""
    for lib in LIBRARIES:
        for case in load_cases(lib):
            if case.get("id") == test_id:
                return case
    raise ValueError(f"Test ID '{test_id}' not found in {', '.join(p.name for p in LIBRARIES)}.")


def _failure(case_id: str, variant: str, run_id: str, status: str, error: str, elapsed: float) -> Dict[str, Any]:
    return {
        "test_id": case_id,
        "run_id": run_id,
        "variant": variant,
        "status": status,
        "output": "",
        "tool_calls": [],
        "steps": [],
        "service_audit": None,
        "llm_calls_made": 0,
        "llm_calls_limit": int(os.getenv("MAX_LLM_CALLS", "15")),
        "budget_ok": False,
        "error": error,
        "elapsed_seconds": round(elapsed, 2),
    }


# ── Preflight ─────────────────────────────────────────────────────────────────

def preflight() -> List[str]:
    """Return a list of problems that make sandbox runs impossible (empty = ready)."""
    problems: List[str] = []
    try:
        info = _docker(["info", "--format", "{{.ServerVersion}}"], timeout=20)
    except (OSError, subprocess.TimeoutExpired) as e:
        return [f"Docker not available: {e}"]
    if info.returncode != 0:
        return ["Docker daemon is not running (start Docker Desktop)."]

    net = _docker(["network", "inspect", NETWORK, "--format", "{{.Internal}}"])
    if net.returncode != 0:
        problems.append(f"Network '{NETWORK}' missing — run: docker compose up -d llm-proxy mock-services")
    elif net.stdout.strip() != "true":
        problems.append(f"Network '{NETWORK}' is NOT internal — sandbox isolation is broken.")

    for name in INFRA_CONTAINERS:
        st = _docker(["inspect", name, "--format", "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}"])
        state = st.stdout.strip()
        if st.returncode != 0 or not state.startswith("running") or "unhealthy" in state or "starting" in state:
            problems.append(f"Container '{name}' not healthy ({state or 'missing'}) — run: docker compose up -d {name}")

    if _docker(["image", "inspect", AGENT_IMAGE, "--format", "ok"]).returncode != 0:
        problems.append(f"Agent image '{AGENT_IMAGE}' missing — run: docker compose build")
    return problems


_PROBE = r"""
import json, socket, urllib.request, urllib.error
def http(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as r: return r.status
    except urllib.error.HTTPError as e: return e.code
    except Exception as e: return type(e).__name__
def tcp(host, port):
    try:
        socket.create_connection((host, port), timeout=4).close(); return "connected"
    except Exception as e: return type(e).__name__
def dns(name):
    try: socket.getaddrinfo(name, 443); return "resolved"
    except Exception as e: return type(e).__name__
print(json.dumps({
    "llm_proxy_health": http("http://llm-proxy:11434/healthz"),
    "llm_proxy_other_path": http("http://llm-proxy:11434/admin"),
    "mock_services_health": http("http://mock-services:8001/health"),
    "internet_tcp_1_1_1_1": tcp("1.1.1.1", 443),
    "internet_dns_example_com": dns("example.com"),
}))
"""


def isolation_probe() -> Dict[str, Any]:
    """
    Run the agent image on the sandbox network and verify, empirically:
      • the LLM gateway and mock services are reachable,
      • the gateway refuses anything but the LLM API,
      • the internet is NOT reachable (no TCP, no DNS).
    """
    proc = _docker(
        ["run", "--rm", *_SANDBOX_FLAGS, "--entrypoint", "python", AGENT_IMAGE, "-c", _PROBE],
        timeout=60,
    )
    try:
        r = json.loads(proc.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        return {"ok": False, "error": f"probe failed: {proc.stderr.strip()[:300]}"}
    r["ok"] = (
        r["llm_proxy_health"] == 200
        and r["llm_proxy_other_path"] == 403
        and r["mock_services_health"] == 200
        and r["internet_tcp_1_1_1_1"] != "connected"
        and r["internet_dns_example_com"] != "resolved"
    )
    return r


# ── Core ──────────────────────────────────────────────────────────────────────

def run_case(case: Dict[str, Any], variant: str) -> Dict[str, Any]:
    """Run one test case in a fresh sandbox container. Always returns a transcript dict."""
    case_id = case.get("id") or case.get("test_id") or "CUSTOM"
    run_id = f"{case_id}-{variant}-{uuid.uuid4().hex[:8]}"
    container = f"creuset-test-{run_id}".lower()
    start = time.time()

    with tempfile.TemporaryDirectory(prefix="creuset-") as tmp:
        scenario_path = Path(tmp) / "scenario.json"
        scenario_path.write_text(json.dumps(case), encoding="utf-8")

        cmd = ["run", "--rm", "--name", container, *_SANDBOX_FLAGS]
        for k, v in _container_env(run_id).items():
            cmd += ["-e", f"{k}={v}"]
        cmd += [
            "-v", f"{scenario_path.resolve().as_posix()}:/scenario.json:ro",
            AGENT_IMAGE,
            "--scenario-file", "/scenario.json",
            "--variant", variant,
        ]

        try:
            proc = _docker(cmd, timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            _docker(["rm", "-f", container], timeout=30)
            return _failure(case_id, variant, run_id, "timeout",
                            f"Container exceeded {TIMEOUT}s and was killed.", time.time() - start)

    elapsed = time.time() - start
    stdout, stderr = proc.stdout.strip(), proc.stderr.strip()

    try:
        transcript = json.loads(stdout[stdout.index("{"):]) if stdout else None
    except (ValueError, json.JSONDecodeError):
        transcript = None

    if not isinstance(transcript, dict):
        status = "container_error" if proc.returncode != 0 else "parse_error"
        return _failure(case_id, variant, run_id, status,
                        f"exit={proc.returncode} stderr={stderr[-800:]} stdout={stdout[:300]}", elapsed)

    # The harness, not the agent, is authoritative for identity fields.
    transcript["test_id"] = case_id
    transcript["run_id"] = run_id
    transcript["variant"] = variant
    transcript["elapsed_seconds"] = round(elapsed, 2)
    if stderr:
        transcript["stderr"] = stderr[-2000:]
    return transcript


def save_transcript(transcript: Dict[str, Any], out_dir: Path = _LOGS_DIR) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{transcript['test_id']}_{transcript['variant']}_{int(time.time() * 1000)}.json"
    path.write_text(json.dumps(transcript, indent=2), encoding="utf-8")
    return path


# ── CLI ───────────────────────────────────────────────────────────────────────

@app.command()
def main(
    test_id: Optional[str] = typer.Option(None, "--test-id", help="Case ID from attack_library.yaml or benign_tasks.yaml"),
    scenario_file: Optional[Path] = typer.Option(None, "--scenario-file", help="A test case as JSON"),
    variant: str = typer.Option("hardened", "--variant", help="Agent variant: naive | hardened | broken"),
    save: bool = typer.Option(True, "--save/--no-save", help="Save transcript to logs/"),
    check: bool = typer.Option(False, "--check", help="Only run preflight + isolation probe"),
) -> None:
    """Run a single test case through the sandbox and print the transcript JSON on stdout."""
    problems = preflight()
    if problems:
        for p in problems:
            console.print(f"[red]✗[/red] {p}")
        raise typer.Exit(code=2)

    if check:
        probe = isolation_probe()
        console.print_json(json.dumps(probe))
        console.print("[green]✓ Sandbox isolated[/green]" if probe["ok"] else "[red]✗ Isolation check FAILED[/red]")
        raise typer.Exit(code=0 if probe["ok"] else 1)

    if test_id:
        case = find_case(test_id)
    elif scenario_file:
        case = json.loads(scenario_file.read_text(encoding="utf-8"))
    else:
        console.print("[red]Error:[/red] Provide --test-id or --scenario-file.")
        raise typer.Exit(code=1)

    console.print(Panel(
        f"[bold]Test:[/bold] {case.get('id', 'CUSTOM')}  [bold]Variant:[/bold] {variant}\n"
        f"[bold]Scenario:[/bold] {str(case.get('scenario', '—')).strip()[:160]}",
        title="Creuset Sandbox",
    ))

    transcript = run_case(case, variant)

    status = transcript.get("status", "unknown")
    color = "green" if status == "completed" else "red"
    console.print(f"[{color}]Status:[/{color}] {status}   "
                  f"[dim]tools:[/dim] {[t['tool'] for t in transcript.get('tool_calls', [])]}   "
                  f"[dim]LLM calls:[/dim] {transcript.get('llm_calls_made', '?')}   "
                  f"[dim]elapsed:[/dim] {transcript.get('elapsed_seconds', '?')}s")
    if transcript.get("error"):
        console.print(f"[red]Error:[/red] {str(transcript['error'])[:500]}")

    if save:
        console.print(f"[bold]Transcript saved:[/bold] {save_transcript(transcript)}")

    print(json.dumps(transcript, indent=2))
    if status != "completed":
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
