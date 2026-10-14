"""
sandbox/run_test.py
────────────────────
Per-test harness: runs ONE test case in a fresh, locked-down agent container,
captures the transcript, and guarantees the container is gone afterwards.

What is under test (the "subject") is either
  • the bundled agent at one variant (agent/variants/<variant>.txt), run from
    AGENT_IMAGE_TAG with --scenario-file/--variant, or
  • any other image (--agent-image / CREUSET_AGENT_IMAGE) that honours the
    contract in sandbox/contract.py: read CREUSET_SCENARIO_FILE, call tools
    through CREUSET_MOCK_URL and the LLM through OPENAI_BASE_URL, print one
    JSON transcript on stdout. Its variant is just a label.

Per case:
  1. The harness creates the run's mock world itself (fixtures and canned tool
     responses), so the attack is in place before the agent starts and an agent
     that never initialises a world still acts in the right one.
  2. docker run --rm --name creuset-test-<run_id>
       --network creuset-net            # internal: true — no internet
       --read-only --tmpfs /tmp:...     # immutable filesystem; scratch is noexec
       --cap-drop ALL --security-opt no-new-privileges --pids-limit 256
       --memory 512m --cpus 1.0
       -e ... (explicit allowlist; the real LLM key is NOT passed — llm-proxy injects it)
       -v <scenario.json>:/scenario.json:ro   # agent_scenario(case): no answer key
       <image ID>                       # the bytes that ran, not a movable tag
  3. The transcript is parsed and checked against the contract, every field the
     harness owns is replaced with its own observation, and the audit log is
     fetched from mock-services directly.

On timeout the container is force-removed (killing the docker CLI alone would
leave it running). Any failure produces a transcript with a non-"completed"
status, which the judge treats as FAIL (fail-closed).

Usage:
  python sandbox/run_test.py --test-id PI-001 --variant naive
  python sandbox/run_test.py --test-id BN-005 --variant hardened
  python sandbox/run_test.py --scenario-file my_case.json --variant hardened
  python sandbox/run_test.py --library my_cases.yaml --test-id ORD-001 \\
      --agent-image my-agent:1.4 --variant v1.4
  python sandbox/run_test.py --check          # preflight + isolation probe only
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import typer
import yaml
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel

sys.path.insert(0, str(Path(__file__).resolve().parent))
from contract import (  # noqa: E402
    SCENARIO_MOUNT, TRANSCRIPT_SCHEMA_VERSION, agent_scenario, exit_code_problem,
    parse_agent_stdout, validate_transcript, without_harness_fields,
)


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
# CREUSET_PREFIX lets a second stack (a CI job beside a dev stack, a second
# checkout) run with its own containers and networks. docker-compose.yml applies
# the same prefix to the same names. The DNS names agents use inside the network
# (mock-services, llm-proxy) are compose service names and do not change.
PREFIX = os.getenv("CREUSET_PREFIX", "")
if not re.fullmatch(r"(?:[a-z0-9][a-z0-9_-]{0,31})?", PREFIX):
    # It becomes part of container and network names, which allow nothing else.
    raise SystemExit(f"CREUSET_PREFIX={PREFIX!r}: lower-case letters, digits, '-' and '_' only")
NETWORK = f"{PREFIX}creuset-net"
MOCK_CONTAINER = f"{PREFIX}mock-services"
LLM_PROXY_CONTAINER = f"{PREFIX}llm-proxy"
INFRA_CONTAINERS = (LLM_PROXY_CONTAINER, MOCK_CONTAINER)
AGENT_IMAGE = os.getenv("AGENT_IMAGE_TAG", "creuset-agent:latest")   # the bundled agent
TIMEOUT = int(os.getenv("SANDBOX_TIMEOUT_SECONDS", "180"))
_MOCK_URL = "http://mock-services:8001"   # as agents inside the network see it
_VARIANTS_DIR = _ROOT / "agent" / "variants"
_VARIANT_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
# A docker image reference or ID. Starting with a letter or digit is what
# matters: it reaches `docker run` as an argument, and "-..." would be an option.
_IMAGE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}$")
# A case id becomes part of a container name, a run id and a file name. The
# library schema is stricter; this is the sink, for --scenario-file and callers
# that never went through the loader.
_CASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def validate_variant(variant: str) -> Optional[str]:
    """
    Why the bundled agent cannot run `variant`, or None if it can.

    The name ends up in a container argument, a mock-services run id and the
    batch directory under logs/runs/ — so `../x` must never get that far.
    """
    problem = validate_label(variant)
    if problem:
        return problem
    if not (_VARIANTS_DIR / f"{variant}.txt").is_file():
        known = sorted(p.stem for p in _VARIANTS_DIR.glob("*.txt"))
        return f"unknown variant {variant!r}; known: {', '.join(known)}"
    return None


def validate_label(variant: str) -> Optional[str]:
    """The alphabet check alone: what an external image's variant label must meet."""
    if not _VARIANT_NAME.fullmatch(variant or ""):
        return f"invalid variant {variant!r}: 1-64 letters, digits, '-' and '_' only"
    return None


# ── Subject: what is under test ───────────────────────────────────────────────

@dataclass(frozen=True)
class Subject:
    """The agent under test: an image, and the variant label it runs as."""
    image: str
    variant: str
    bundled: bool

    def args(self) -> List[str]:
        # An external image runs its own ENTRYPOINT/CMD and finds the scenario
        # through CREUSET_SCENARIO_FILE; only the bundled agent takes flags.
        if self.bundled:
            return ["--scenario-file", SCENARIO_MOUNT, "--variant", self.variant]
        return []

    def describe(self) -> Dict[str, Any]:
        return {"kind": "bundled" if self.bundled else "external",
                "image": self.image, "variant": self.variant}


def subject_problem(variant: str, agent_image: Optional[str] = None) -> Optional[str]:
    """Why (variant, agent_image) cannot be run, or None."""
    if not agent_image:
        return validate_variant(variant)
    if not _IMAGE_REF.fullmatch(agent_image):
        return f"invalid image reference {agent_image!r}"
    return validate_label(variant)


def make_subject(variant: str, agent_image: Optional[str] = None) -> Subject:
    """The subject for (variant, agent_image); raises ValueError if it cannot run."""
    problem = subject_problem(variant, agent_image)
    if problem:
        raise ValueError(problem)
    if agent_image:
        return Subject(image=agent_image, variant=variant, bundled=False)
    return Subject(image=AGENT_IMAGE, variant=variant, bundled=True)


# The ONLY environment a test container receives.
def _container_env(run_id: str, variant: str) -> Dict[str, str]:
    llm_base = os.getenv("AGENT_API_BASE", "http://llm-proxy:11434/openai/v1")
    return {
        # The contract (sandbox/contract.py CONTRACT_ENV).
        "CREUSET_CONTRACT_VERSION": str(TRANSCRIPT_SCHEMA_VERSION),
        "CREUSET_SCENARIO_FILE": SCENARIO_MOUNT,
        "CREUSET_RUN_ID": run_id,
        "CREUSET_VARIANT": variant,
        "CREUSET_MOCK_URL": f"{_MOCK_URL}/r/{quote(run_id, safe='')}",
        "OPENAI_BASE_URL": llm_base,
        "OPENAI_API_BASE": llm_base,
        "OPENAI_API_KEY": "sandbox-placeholder-key",  # real key injected by llm-proxy
        "AGENT_MODEL": os.getenv("AGENT_MODEL", "gpt-4o-mini"),
        # The bundled agent's knobs. Harmless to any other image.
        "MOCK_SERVICES_HOST": "mock-services",
        "MOCK_SERVICES_PORT": "8001",
        "MAX_LLM_CALLS": os.getenv("MAX_LLM_CALLS", "15"),
        "LLM_MAX_RETRIES": os.getenv("LLM_MAX_RETRIES", "8"),
        "AGENT_MAX_TOKENS": os.getenv("AGENT_MAX_TOKENS", "700"),
        # Separate from AGENT_MAX_TOKENS on purpose: the empty-answer finalizer
        # needs room for a whole answer, not one step of a tool-calling loop.
        "FINALIZER_MAX_TOKENS": os.getenv("FINALIZER_MAX_TOKENS", "1024"),
    }


def _sandbox_flags() -> List[str]:
    return [
        "--network", NETWORK,
        "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", "256",
        "--memory", "512m",
        "--cpus", "1.0",
        "--no-healthcheck",
    ]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _docker(args: List[str], timeout: int = 60, input: Optional[str] = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout,
        encoding="utf-8", errors="replace", input=input,
    )


def load_cases(path: Path) -> List[Dict[str, Any]]:
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    return raw if isinstance(raw, list) else raw.get("cases", [])


def find_case(test_id: str, libraries: Optional[List[Path]] = None) -> Dict[str, Any]:
    """Look a case up by id in the given libraries (default: attacks + benign tasks)."""
    libraries = libraries or LIBRARIES
    for lib in libraries:
        for case in load_cases(lib):
            if case.get("id") == test_id:
                return case
    raise ValueError(f"Test ID '{test_id}' not found in {', '.join(p.name for p in libraries)}.")


def image_id(image: str) -> Optional[str]:
    """The ID `image` resolves to now, or None if there is no such local image."""
    try:
        proc = _docker(["image", "inspect", image, "--format", "{{.Id}}"], timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    ident = proc.stdout.strip()
    return ident if proc.returncode == 0 and ident else None


def _failure(case_id: str, subject: Subject, run_id: str, status: str, error: str, elapsed: float,
             image_ref: Optional[str] = None, **extra: Any) -> Dict[str, Any]:
    return {
        "test_id": case_id,
        "run_id": run_id,
        "variant": subject.variant,
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
        "agent_image": subject.image,
        "agent_image_id": image_ref,
        **extra,
    }


# ── Preflight ─────────────────────────────────────────────────────────────────

def preflight(subject: Optional[Subject] = None) -> List[str]:
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
            problems.append(f"Container '{name}' not healthy ({state or 'missing'}) — run: docker compose up -d")

    image = subject.image if subject else AGENT_IMAGE
    if image_id(image) is None:
        hint = "docker compose build agent-blue" if (subject is None or subject.bundled) else f"docker pull {image}"
        problems.append(f"Agent image '{image}' missing — run: {hint}")
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
    Start a container on the sandbox network, with the sandbox's flags, and
    verify empirically:
      • the LLM gateway and mock services are reachable,
      • the gateway refuses anything but the LLM API,
      • the internet is NOT reachable (no TCP, no DNS).

    It runs mock-services' own image: isolation is a property of the network,
    and that image is always present and always has Python, whereas an external
    agent image may have neither.
    """
    inspect = _docker(["inspect", MOCK_CONTAINER, "--format", "{{.Image}}"])
    probe_image = inspect.stdout.strip()
    if inspect.returncode != 0 or not probe_image:
        return {"ok": False, "error": f"container '{MOCK_CONTAINER}' not found; start the infrastructure first"}
    proc = _docker(
        ["run", "--rm", *_sandbox_flags(), "--entrypoint", "python", probe_image, "-c", _PROBE],
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


# ── Mock world (talked to from inside its own container) ──────────────────────
# Only the harness may create a world or read an audit log; neither is reachable
# from the host by design (mock-services publishes no port), so both go through
# `docker exec` and the image's own Python — the one tool it cannot lose.

_WORLD_INIT = ("import sys, urllib.request; "
               "r = urllib.request.Request(sys.argv[1], data=sys.stdin.buffer.read(), method='POST', "
               "headers={'Content-Type': 'application/json'}); "
               "sys.stdout.write(urllib.request.urlopen(r, timeout=10).read().decode())")
_AUDIT_FETCH = ("import sys, urllib.request; "
                "sys.stdout.write(urllib.request.urlopen(sys.argv[1], timeout=10).read().decode())")


def init_world(run_id: str, fixtures: List[str], responses: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """
    Create the run's world before the agent starts. Returns why it failed, or None.

    mock-services creates a world once and never resets it, so the bundled
    agent's own init call afterwards (same fixtures) is a harmless repeat. The
    body goes over stdin: canned responses can be far larger than a Windows
    command line.
    """
    url = f"http://localhost:8001/runs/{quote(run_id, safe='')}/init"
    body = json.dumps({"fixtures": list(fixtures), "responses": responses or {}})
    try:
        proc = _docker(["exec", "-i", MOCK_CONTAINER, "python", "-c", _WORLD_INIT, url],
                       timeout=30, input=body)
    except (OSError, subprocess.TimeoutExpired) as e:
        return f"{type(e).__name__}: {e}"
    if proc.returncode != 0:
        # urlopen raises on 4xx (unknown fixture, oversized response), so the
        # reason is in the traceback's last line.
        lines = proc.stderr.strip().splitlines()
        return lines[-1][:300] if lines else f"exit {proc.returncode}"
    try:
        created = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return f"unexpected reply: {proc.stdout[:200]!r}"
    if not isinstance(created, dict) or sorted(created.get("fixtures") or []) != sorted(fixtures):
        return f"world was not created with fixtures {sorted(fixtures)}: {proc.stdout[:200]!r}"
    return None


def fetch_world(run_id: str) -> Optional[Dict[str, Any]]:
    """
    The run's audit record from mock-services — {"entries": [...], "fixtures":
    [...]} — read by the HARNESS once the agent container has exited.

    The bundled agent also fetches its audit log and reports it on stdout, but
    that copy is relayed by the very process under test. Ground truth the
    subject can edit is not ground truth, so the harness's copy replaces it.
    None = unavailable, which the rule layer fails closed.
    """
    url = f"http://localhost:8001/audit/log?run={quote(run_id, safe='')}"
    try:
        # urlopen raises on a 404 (unknown run), so that exits non-zero.
        proc = _docker(["exec", MOCK_CONTAINER, "python", "-c", _AUDIT_FETCH, url], timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        record = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(record, dict) or not isinstance(record.get("entries"), list):
        return None
    return record


def fetch_audit(run_id: str) -> Optional[List[Dict[str, Any]]]:
    """Just the audit entries of fetch_world(), or None if unavailable."""
    record = fetch_world(run_id)
    return None if record is None else record["entries"]


# ── Core ──────────────────────────────────────────────────────────────────────

def run_case(case: Dict[str, Any], variant: str, subject: Optional[Subject] = None) -> Dict[str, Any]:
    """
    Run one test case in a fresh sandbox container. Always returns a transcript
    dict; anything that goes wrong is a non-"completed" status (fail-closed).

    `subject` defaults to the bundled agent at `variant`.
    """
    subject = subject or Subject(image=AGENT_IMAGE, variant=variant, bundled=True)
    case_id = case.get("id") or case.get("test_id") or "CUSTOM"
    if not isinstance(case_id, str) or not _CASE_ID.fullmatch(case_id) or ".." in case_id:
        return _failure("INVALID-ID", subject, "none", "harness_error",
                        f"Case id {case_id!r} is not usable: 1-64 letters, digits, '.', '-' and '_'.", 0.0)
    fixtures = list(case.get("fixtures") or [])
    run_id = f"{case_id}-{subject.variant}-{uuid.uuid4().hex[:8]}"
    container = f"creuset-test-{run_id}".lower()
    setup_start = time.time()

    # Run by ID, resolved once: a tag can be re-pointed by a rebuild mid-batch,
    # and the transcript has to name the bytes that actually produced it.
    image_ref = image_id(subject.image)
    if image_ref is None:
        return _failure(case_id, subject, run_id, "harness_error",
                        f"Agent image '{subject.image}' not found locally.", time.time() - setup_start)

    problem = init_world(run_id, fixtures, case.get("tool_responses"))
    if problem:
        return _failure(case_id, subject, run_id, "harness_error",
                        f"Could not create the run's mock world: {problem}", time.time() - setup_start,
                        image_ref)

    start = time.time()  # elapsed_seconds is the container's wall time, not the setup's

    with tempfile.TemporaryDirectory(prefix="creuset-") as tmp:
        scenario_path = Path(tmp) / "scenario.json"
        # Only what the agent may read: never the answer key (expected_behavior,
        # forbidden_tools, patterns...), which an agent could otherwise read.
        scenario_path.write_text(json.dumps(agent_scenario(case)), encoding="utf-8")

        cmd = ["run", "--rm", "--name", container, *_sandbox_flags()]
        for k, v in _container_env(run_id, subject.variant).items():
            cmd += ["-e", f"{k}={v}"]
        cmd += ["-v", f"{scenario_path.resolve().as_posix()}:{SCENARIO_MOUNT}:ro",
                image_ref, *subject.args()]

        try:
            proc = _docker(cmd, timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            _docker(["rm", "-f", container], timeout=30)
            return _failure(case_id, subject, run_id, "timeout",
                            f"Container exceeded {TIMEOUT}s and was killed.", time.time() - start,
                            image_ref)

    elapsed = time.time() - start
    return _finish(case_id, subject, run_id, image_ref, fixtures, proc, elapsed)


def _finish(case_id: str, subject: Subject, run_id: str, image_ref: str, fixtures: List[str],
            proc: subprocess.CompletedProcess, elapsed: float) -> Dict[str, Any]:
    """Turn a finished container into a transcript the judge can trust."""
    stdout, stderr = (proc.stdout or "").strip(), (proc.stderr or "").strip()

    parsed, parse_problem = parse_agent_stdout(stdout)
    if parsed is None:
        status = "container_error" if proc.returncode != 0 else "parse_error"
        return _failure(case_id, subject, run_id, status,
                        f"{parse_problem} exit={proc.returncode} stderr={stderr[-800:]} "
                        f"stdout={stdout[:300]}", elapsed, image_ref, exit_code=proc.returncode)

    violations = validate_transcript(parsed)
    contradiction = exit_code_problem(parsed, proc.returncode)

    # The harness, not the agent, is authoritative for identity fields — and for
    # what the run actually did. Dropping them first means a field the harness
    # leaves unset (stderr, when there was none) cannot keep the agent's value.
    transcript = without_harness_fields(parsed)
    transcript.update({
        "test_id": case_id,
        "run_id": run_id,
        "variant": subject.variant,
        "elapsed_seconds": round(elapsed, 2),
        "agent_image": subject.image,
        "agent_image_id": image_ref,
        "exit_code": proc.returncode,
    })
    if stderr:
        transcript["stderr"] = stderr[-2000:]

    world = fetch_world(run_id)
    transcript["service_audit"] = None if world is None else world["entries"]
    transcript["audit_source"] = "harness"
    if world is not None:
        transcript["world_fixtures"] = world.get("fixtures")

    def overrule(status: str, why: str) -> None:
        transcript["reported_status"] = parsed.get("status")
        transcript["status"] = status
        agent_error = parsed.get("error")
        transcript["error"] = why + (f" (agent reported: {agent_error})" if agent_error else "")

    if violations:
        transcript["contract_violations"] = violations[:20]
        overrule("contract_error", "Transcript breaks schemas/transcript.v1.json: " + "; ".join(violations[:3]))
    elif contradiction:
        overrule("container_error", contradiction[0].upper() + contradiction[1:] + ".")
    elif world is not None and sorted(world.get("fixtures") or []) != sorted(fixtures):
        # The attack the case exists to deliver never reached this world (e.g.
        # mock-services restarted mid-run), so a PASS here would mean nothing.
        overrule("harness_error", f"The run's world had fixtures {sorted(world.get('fixtures') or [])}, "
                                  f"not {sorted(fixtures)}.")
    return transcript


def save_transcript(transcript: Dict[str, Any], out_dir: Path = _LOGS_DIR) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{transcript['test_id']}_{transcript['variant']}_{int(time.time() * 1000)}.json"
    path.write_text(json.dumps(transcript, indent=2), encoding="utf-8")
    return path


# ── CLI ───────────────────────────────────────────────────────────────────────

@app.command()
def main(
    test_id: Optional[str] = typer.Option(None, "--test-id", help="Case ID, looked up in --library (default: attack_library.yaml and benign_tasks.yaml)"),
    scenario_file: Optional[Path] = typer.Option(None, "--scenario-file", help="A test case as JSON"),
    library: Optional[List[Path]] = typer.Option(None, "--library", help="Library to look --test-id up in (repeatable)."),
    variant: str = typer.Option("hardened", "--variant", help="Bundled agent: naive | hardened | broken. With --agent-image: any label."),
    agent_image: Optional[str] = typer.Option(None, "--agent-image", envvar="CREUSET_AGENT_IMAGE",
                                              help="Test this image instead of the bundled agent (see sandbox/contract.py)."),
    save: bool = typer.Option(True, "--save/--no-save", help="Save transcript to logs/"),
    check: bool = typer.Option(False, "--check", help="Only run preflight + isolation probe"),
) -> None:
    """Run a single test case through the sandbox and print the transcript JSON on stdout."""
    try:
        subject = make_subject(variant, agent_image)
    except ValueError as e:
        console.print(f"[red]✗[/red] {e}")
        raise typer.Exit(code=2)
    problems = preflight(subject)
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
        try:
            case = find_case(test_id, library or None)
        except (OSError, ValueError) as e:
            console.print(f"[red]Error:[/red] {e}")
            raise typer.Exit(code=2)
    elif scenario_file:
        case = json.loads(scenario_file.read_text(encoding="utf-8"))
    else:
        console.print("[red]Error:[/red] Provide --test-id or --scenario-file.")
        raise typer.Exit(code=1)

    console.print(Panel(
        f"[bold]Test:[/bold] {case.get('id', 'CUSTOM')}  [bold]Variant:[/bold] {subject.variant}"
        + ("" if subject.bundled else f"  [bold]Image:[/bold] {subject.image}") + "\n"
        f"[bold]Scenario:[/bold] {str(case.get('scenario', '—')).strip()[:160]}",
        title="Creuset Sandbox",
    ))

    transcript = run_case(case, subject.variant, subject)

    status = transcript.get("status", "unknown")
    color = "green" if status == "completed" else "red"
    tools = [t.get("tool") for t in transcript.get("tool_calls") or [] if isinstance(t, dict)]
    console.print(f"[{color}]Status:[/{color}] {status}   "
                  f"[dim]tools:[/dim] {tools}   "
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
