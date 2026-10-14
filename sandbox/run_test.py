"""
sandbox/run_test.py
────────────────────
Per-test harness: runs ONE test case in a fresh, locked-down agent container,
captures the transcript, and guarantees the container is gone afterwards.

For each case the harness, not the agent under test:
  1. resolves the agent image to an image ID, once per process, and runs every
     case by that ID, so a rebuild halfway through a batch cannot mix builds.
     The image is --image, else AGENT_IMAGE, else AGENT_IMAGE_TAG (the tag
     compose builds ./agent as), else creuset-agent:latest;
  2. creates the run's world in mock-services (the case's fixtures and canned
     `mock_responses`) before the agent starts. The subject never sets up the
     world it is judged in;
  3. hands the agent contract.agent_scenario(case) only, never a grading field;
  4. runs it:
       docker run --rm --name creuset-test-<run_id>
         --network creuset-net            # internal: true, no internet
         --read-only --tmpfs /tmp:...     # immutable filesystem; scratch is noexec
         --cap-drop ALL --security-opt no-new-privileges --pids-limit 256
         --memory 512m --cpus 1.0
         --label creuset.project=creuset --label creuset.run=<run_id>
         [--label creuset.batch=<batch_id>]
         -e ... (explicit allowlist; the real LLM key is NOT passed, llm-proxy injects it)
         -v <scenario.json>:/scenario.json:ro
         <image id> --scenario-file /scenario.json --variant <variant>
  5. reads the transcript from stdout (contract.parse_agent_stdout), validates
     a v1 transcript against schemas/transcript.v1.json, overrules a
     "completed" transcript from a container that exited non-zero, and fills in
     the harness-owned fields (identity, image, effective settings, and the
     mock-services audit log) from its own observations.

On timeout the container is force-removed (killing the docker CLI alone would
leave it running). Any failure produces a transcript with a non-"completed"
status, which the judge treats as FAIL (fail-closed).

Scenario transport (CREUSET_SCENARIO_TRANSPORT)
  bind    (default) a host temp file bind-mounted at /scenario.json.
  volume  a per-case named volume, filled from stdin by a short-lived container
          of the mock-services image and mounted read-only at /creuset-in.
          Use it when the Docker daemon cannot see this machine's files:
          docker-in-docker CI, a remote DOCKER_HOST, Colima. No agent change.

Names (defaults are what docker-compose.yml creates)
  CREUSET_NETWORK          creuset-net
  CREUSET_MOCK_CONTAINER   mock-services
  CREUSET_PROXY_CONTAINER  llm-proxy
  CREUSET_PROJECT          creuset   (the creuset.project label value)

Usage:
  python sandbox/run_test.py --test-id PI-001 --variant naive
  python sandbox/run_test.py --test-id BN-005 --variant hardened
  python sandbox/run_test.py --test-id ACME-001 --library my_cases.yaml --image acme/agent:1.4 --variant prod
  python sandbox/run_test.py --scenario-file my_case.json --variant hardened
  python sandbox/run_test.py --check          # preflight + isolation probe only
  python sandbox/run_test.py --cleanup all    # remove leftover test containers
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import typer
import yaml
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel

# The script is run directly (python sandbox/run_test.py) and imported from
# attacks/loader.py and ui/app.py; contract.py sits beside it either way.
_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
import contract  # noqa: E402


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
PROJECT = os.getenv("CREUSET_PROJECT") or "creuset"
NETWORK = os.getenv("CREUSET_NETWORK") or "creuset-net"
MOCK_CONTAINER = os.getenv("CREUSET_MOCK_CONTAINER") or "mock-services"
PROXY_CONTAINER = os.getenv("CREUSET_PROXY_CONTAINER") or "llm-proxy"
INFRA_CONTAINERS = (PROXY_CONTAINER, MOCK_CONTAINER)
MOCK_PORT = "8001"
# What compose builds ./agent as. The tag is configurable (AGENT_IMAGE_TAG), the
# image it names is the bundled reference agent either way.
BUNDLED_IMAGE = "creuset-agent:latest"
TIMEOUT = int(os.getenv("SANDBOX_TIMEOUT_SECONDS", "180"))
TRANSPORTS = ("bind", "volume")
_VARIANTS_DIR = _ROOT / "agent" / "variants"
_VARIANT_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
# A docker image reference or ID. Checked because it becomes a CLI argument: a
# value starting with '-' would be read as a flag.
_IMAGE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@+-]{0,511}$")
_REBUILD_HINT = "docker compose build agent-blue"
# Every container and volume the harness creates is named <prefix>-<role>-<id>.
_NAME_PREFIX = "creuset"

# Settings the agent's behaviour depends on, recorded in every transcript as the
# values actually passed (harness_config), so a report can show what it measured.
_RECORDED_SETTINGS = ("AGENT_MAX_TOKENS", "FINALIZER_MAX_TOKENS", "MAX_LLM_CALLS")
# Unchanged from before the env was recorded, and identical to docker-compose.yml
# x-agent-env, so a slot runs exactly what the gate tested. AGENT_MAX_TOKENS
# stays 700 although the published runs used 400 (.env.example); changing it
# changes agent behaviour for anyone without a .env value, so preflight_warnings()
# says so instead.
_ENV_DEFAULTS = {
    "MAX_LLM_CALLS": "15",
    "LLM_MAX_RETRIES": "8",
    "AGENT_MAX_TOKENS": "700",
    "FINALIZER_MAX_TOKENS": "1024",
    "LLM_TIMEOUT_SECONDS": "90",
}


def default_image() -> str:
    """The agent image to run when none is named: AGENT_IMAGE, else the bundled tag."""
    return os.getenv("AGENT_IMAGE") or bundled_image_ref()


def bundled_image_ref() -> str:
    """The tag the image built from ./agent carries (AGENT_IMAGE_TAG, the legacy name)."""
    return os.getenv("AGENT_IMAGE_TAG") or BUNDLED_IMAGE


# Kept for importers of the old constant; everything here reads default_image()
# at call time, so a later AGENT_IMAGE is honoured.
AGENT_IMAGE = default_image()


def agent_model() -> Optional[str]:
    """AGENT_MODEL, or None. There is no default: see preflight()."""
    return (os.getenv("AGENT_MODEL") or "").strip() or None


def scenario_transport() -> str:
    return (os.getenv("CREUSET_SCENARIO_TRANSPORT") or "bind").strip().lower()


# ── Docker ────────────────────────────────────────────────────────────────────

def _docker(args: List[str], timeout: int = 60, input: Optional[str] = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout,
        encoding="utf-8", errors="replace", input=input,
    )


def _first_line(text: Optional[str]) -> str:
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    # The daemon's own warnings (e.g. bridge-nf-call-iptables) are not why it failed.
    useful = [ln for ln in lines if not ln.upper().startswith("WARNING")]
    return (useful or lines or [""])[0][:300]


def _last_line(text: Optional[str]) -> str:
    # A Python traceback ends with the exception; its first line says nothing.
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    return lines[-1][:300] if lines else ""


def _labels(run_id: Optional[str] = None, batch_id: Optional[str] = None) -> List[str]:
    """
    Labels on everything the harness starts, so a batch's leftovers can be found
    and removed after a crash or Ctrl-C (remove_batch_containers, --cleanup).
    """
    out = ["--label", f"creuset.project={PROJECT}"]
    if run_id:
        out += ["--label", f"creuset.run={run_id}"]
    if batch_id:
        out += ["--label", f"creuset.batch={batch_id}"]
    return out


_SANDBOX_FLAGS = [
    "--network", NETWORK,
    "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--pids-limit", "256",
    "--memory", "512m",
    "--cpus", "1.0",
    "--no-healthcheck",
]

# For the harness's own short-lived helpers (variant check, volume fill): they
# need no network at all.
_HELPER_FLAGS = [
    "--network", "none",
    "--read-only",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--no-healthcheck",
]


# ── Image ─────────────────────────────────────────────────────────────────────

_image_ids: Dict[str, str] = {}
_image_lock = threading.Lock()


def _missing_image_message(ref: str, detail: str) -> str:
    if ref == bundled_image_ref():
        return f"Agent image '{ref}' not found ({detail}). Build it: {_REBUILD_HINT}"
    return (f"Agent image '{ref}' not found on the Docker daemon ({detail}). "
            f"Build or pull it first (docker pull {ref}).")


def resolve_image(image: Optional[str] = None) -> Tuple[str, str]:
    """
    (ref, image ID) for `image`, else default_image().

    Resolved once per process and cached: every case of a batch then runs the
    same build, by ID, even if the tag is rebuilt while the batch is running.
    Raises RuntimeError with a plain message when the image does not exist.
    """
    ref = (image or default_image()).strip()
    if not _IMAGE_REF.fullmatch(ref):
        raise RuntimeError(f"Invalid agent image reference {ref!r}.")
    with _image_lock:
        cached = _image_ids.get(ref)
        if cached:
            return ref, cached
        try:
            proc = _docker(["image", "inspect", "--format", "{{.Id}}", ref], timeout=30)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise RuntimeError(f"Cannot inspect agent image '{ref}': Docker is not available "
                               f"({type(e).__name__}: {e}).") from e
        image_id = proc.stdout.strip()
        if proc.returncode != 0 or not image_id.startswith("sha256:"):
            raise RuntimeError(_missing_image_message(ref, _first_line(proc.stderr) or "no such image"))
        _image_ids[ref] = image_id
        return ref, image_id


def is_bundled_image(image_id: str) -> bool:
    """Whether `image_id` is the image built from ./agent (the bundled tag's ID)."""
    try:
        _, bundled_id = resolve_image(bundled_image_ref())
    except RuntimeError:
        return False
    return bool(image_id) and image_id == bundled_id


def _uses_bundled_image(image: Optional[str]) -> bool:
    ref = image or default_image()
    if ref == bundled_image_ref():
        return True  # decided without Docker, so the common case needs no daemon
    try:
        _, image_id = resolve_image(ref)
    except RuntimeError:
        return False  # a missing image is preflight's and run_case's to report
    return is_bundled_image(image_id)


# ── Variants ──────────────────────────────────────────────────────────────────

# Prints the sha256 of the image's own copy of a variant, or "missing".
_VARIANT_DIGEST = (
    "import hashlib, sys\n"
    "try:\n"
    "    data = open('/app/variants/' + sys.argv[1] + '.txt', 'rb').read()\n"
    "except FileNotFoundError:\n"
    "    print('missing')\n"
    "else:\n"
    "    print(hashlib.sha256(data).hexdigest())\n"
)
_variant_checks: Dict[Tuple[str, str, str], Optional[str]] = {}
_variant_lock = threading.Lock()


def validate_variant(variant: str, *, image: Optional[str] = None) -> Optional[str]:
    """
    Why `variant` cannot be run, or None if it can.

    The name ends up in a container argument, a mock-services run id and the
    batch directory under logs/runs/, so `../x` must never get that far.

    For the bundled image the variant is a prompt file in agent/variants/, and
    the image must carry the same bytes: variants are baked in at build time,
    so editing the host file without rebuilding would run the OLD prompt while
    every record said the new one. For any other image the variant is passed
    through as an opaque argument, and only its name is checked.
    """
    if not _VARIANT_NAME.fullmatch(variant or ""):
        return f"invalid variant {variant!r}: letters, digits, '-' and '_' only"
    if not _uses_bundled_image(image):
        return None
    if not (_VARIANTS_DIR / f"{variant}.txt").is_file():
        known = sorted(p.stem for p in _VARIANTS_DIR.glob("*.txt"))
        return f"unknown variant {variant!r}; known: {', '.join(known)}"
    return _stale_variant_problem(variant, image)


def _stale_variant_problem(variant: str, image: Optional[str]) -> Optional[str]:
    """Whether the image's copy of the variant differs from the host's. Cached per process."""
    try:
        ref, image_id = resolve_image(image)
    except RuntimeError:
        # Nothing to compare against. preflight() reports the missing image or
        # Docker, and nothing runs without both.
        return None
    # Raw bytes on both sides: a CRLF checkout builds a CRLF image, and that is
    # still the same prompt as far as the build is concerned.
    host = hashlib.sha256((_VARIANTS_DIR / f"{variant}.txt").read_bytes()).hexdigest()
    key = (image_id, variant, host)  # an edit to the host file is a new question
    with _variant_lock:
        if key not in _variant_checks:
            _variant_checks[key] = _compare_variant(variant, ref, image_id, host)
        return _variant_checks[key]


def _compare_variant(variant: str, ref: str, image_id: str, host: str) -> Optional[str]:
    image_name = f"image '{ref}' ({image_id[7:19]})"
    check = f"check-{uuid.uuid4().hex[:8]}"
    name = f"{_NAME_PREFIX}-{check}"
    try:
        proc = _docker(["run", "--rm", "--name", name, *_HELPER_FLAGS, *_labels(check),
                        "--entrypoint", "python", image_id, "-c", _VARIANT_DIGEST, variant], timeout=60)
    except (OSError, subprocess.TimeoutExpired) as e:
        _remove_quietly(name)
        return f"Could not read variant {variant!r} from {image_name}: {type(e).__name__}: {e}"
    found = proc.stdout.strip()
    if proc.returncode != 0 or not found:
        return (f"Could not read variant {variant!r} from {image_name}: "
                f"{_last_line(proc.stderr) or f'exit {proc.returncode}'}")
    if found == "missing":
        return (f"variant {variant!r} is not in {image_name}: agent/variants/{variant}.txt was added "
                f"after the image was built. Rebuild it: {_REBUILD_HINT}")
    if found != host:
        return (f"agent/variants/{variant}.txt differs from the copy inside {image_name}, so the "
                f"container would run the OLD prompt. Rebuild it: {_REBUILD_HINT}")
    return None


def _canary_markers() -> Optional[List[str]]:
    """judge/rule_checks.canary_markers(), so the harness and the rule layer agree."""
    try:
        module = sys.modules.get("rule_checks")
        if module is None:
            judge = str(_ROOT / "judge")
            if judge not in sys.path:
                sys.path.append(judge)
            import rule_checks as module  # lazy: only warnings need it
        return list(module.canary_markers())
    except Exception:  # pylint: disable=broad-except — a warning must never block a run
        return None


def canary_warning(variant: str, *, image: Optional[str] = None) -> Optional[str]:
    """
    A warning when the bundled variant's prompt carries none of the canary
    markers: the canary check would then pass every case without being able
    to see a leak. None for other images, whose prompt the harness cannot read.
    """
    if not _VARIANT_NAME.fullmatch(variant or "") or not _uses_bundled_image(image):
        return None
    try:
        text = (_VARIANTS_DIR / f"{variant}.txt").read_text(encoding="utf-8")
    except OSError:
        return None
    markers = _canary_markers()
    if not markers:  # unknown, or deliberately off (the rule layer then SKIPs the check)
        return None
    if any(marker in text for marker in markers):
        return None
    return (f"agent/variants/{variant}.txt contains no canary marker ({', '.join(markers)}), so the "
            f"canary check cannot detect a leak of this prompt. Add the marker to the prompt, or set "
            f"CREUSET_CANARY to the marker it carries (empty: no canary, and the check is skipped).")


# ── Environment ───────────────────────────────────────────────────────────────

def _setting(name: str) -> str:
    # Empty counts as unset, as compose's ${VAR:-default} treats it.
    return os.getenv(name) or _ENV_DEFAULTS[name]


def _tools_url(run_id: str) -> str:
    return f"http://{MOCK_CONTAINER}:{MOCK_PORT}/r/{quote(run_id, safe='')}"


# The ONLY environment a test container receives.
def _container_env(run_id: str) -> Dict[str, str]:
    api_base = os.getenv("AGENT_API_BASE") or f"http://{PROXY_CONTAINER}:11434/openai/v1"
    return {
        "OPENAI_API_BASE": api_base,
        "OPENAI_API_KEY": "sandbox-placeholder-key",  # real key injected by llm-proxy
        "AGENT_MODEL": agent_model() or "",  # run_case refuses to start without it
        "MOCK_SERVICES_HOST": MOCK_CONTAINER,
        "MOCK_SERVICES_PORT": MOCK_PORT,
        "MAX_LLM_CALLS": _setting("MAX_LLM_CALLS"),
        "LLM_MAX_RETRIES": _setting("LLM_MAX_RETRIES"),
        "AGENT_MAX_TOKENS": _setting("AGENT_MAX_TOKENS"),
        # Separate from AGENT_MAX_TOKENS on purpose: the empty-answer finalizer
        # needs room for a whole answer, not one step of a tool-calling loop.
        "FINALIZER_MAX_TOKENS": _setting("FINALIZER_MAX_TOKENS"),
        "CREUSET_RUN_ID": run_id,
        # The name the official openai SDK reads. Neutral for the bundled agent,
        # which passes OPENAI_API_BASE explicitly; without it, an agent on the
        # plain SDK would try api.openai.com, which the sandbox cannot reach.
        "OPENAI_BASE_URL": api_base,
        "LLM_TIMEOUT_SECONDS": _setting("LLM_TIMEOUT_SECONDS"),
        # Run-scoped tool base URL: an agent whose HTTP client cannot add the
        # X-Creuset-Run header re-points its base URL here instead.
        "CREUSET_TOOLS_URL": _tools_url(run_id),
    }


def _config_problems() -> List[str]:
    problems: List[str] = []
    if not agent_model():
        problems.append("AGENT_MODEL is not set. Put it in .env (see .env.example, e.g. "
                        "AGENT_MODEL=openai/gpt-oss-20b); the harness no longer falls back to gpt-4o-mini, "
                        "which a non-OpenAI upstream would refuse on every case.")
    if scenario_transport() not in TRANSPORTS:
        problems.append(f"CREUSET_SCENARIO_TRANSPORT={scenario_transport()!r}: expected one of "
                        f"{', '.join(TRANSPORTS)}.")
    return problems


def preflight_warnings() -> List[str]:
    """Settings worth a look that do not stop a run."""
    warnings: List[str] = []
    if not os.getenv("AGENT_MAX_TOKENS"):
        warnings.append(f"AGENT_MAX_TOKENS is not set, so agent containers get "
                        f"{_ENV_DEFAULTS['AGENT_MAX_TOKENS']}. The published results used 400 "
                        f"(.env.example); set it to compare like with like.")
    return warnings


# ── Cases ─────────────────────────────────────────────────────────────────────

def load_cases(path: Path) -> List[Dict[str, Any]]:
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    return raw if isinstance(raw, list) else (raw or {}).get("cases", [])


def find_case(test_id: str, library: Optional[Path] = None) -> Dict[str, Any]:
    """Look a case up by id in `library`, else in the attack library and the benign task set."""
    libraries = [Path(library)] if library else LIBRARIES
    for lib in libraries:
        for case in load_cases(lib):
            if case.get("id") == test_id:
                return case
    raise ValueError(f"Test ID '{test_id}' not found in {', '.join(p.name for p in libraries)}.")


def _name_part(text: str) -> str:
    # Case ids from a custom scenario file end up in container, volume and file
    # names: keep only characters all three accept, and never a path separator.
    return re.sub(r"[^A-Za-z0-9_.-]", "_", text)[:64] or "X"


# ── Preflight ─────────────────────────────────────────────────────────────────

def preflight(image: Optional[str] = None) -> List[str]:
    """Return a list of problems that make sandbox runs impossible (empty = ready)."""
    problems = _config_problems()
    try:
        info = _docker(["info", "--format", "{{.ServerVersion}}"], timeout=20)
    except (OSError, subprocess.TimeoutExpired) as e:
        return problems + [f"Docker not available: {e}"]
    if info.returncode != 0:
        detail = _first_line(info.stderr) or _first_line(info.stdout) or f"exit {info.returncode}"
        return problems + [f"Docker daemon is not reachable: {detail} (start Docker Desktop or the "
                           f"Docker service, or check DOCKER_HOST / `docker context`)."]

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

    try:
        resolve_image(image)
    except RuntimeError as e:
        problems.append(str(e))
    return problems


_PROBE = r"""
import json, socket, sys, urllib.request, urllib.error
proxy, mock = sys.argv[1], sys.argv[2]
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
    "llm_proxy_health": http("http://%s:11434/healthz" % proxy),
    "llm_proxy_other_path": http("http://%s:11434/admin" % proxy),
    "mock_services_health": http("http://%s:8001/health" % mock),
    "internet_tcp_1_1_1_1": tcp("1.1.1.1", 443),
    "internet_dns_example_com": dns("example.com"),
}))
"""


def _mock_image() -> Optional[str]:
    """The image ID the running mock-services container was created from."""
    try:
        proc = _docker(["inspect", "--format", "{{.Image}}", MOCK_CONTAINER], timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    image_id = proc.stdout.strip()
    return image_id if proc.returncode == 0 and image_id.startswith("sha256:") else None


def isolation_probe() -> Dict[str, Any]:
    """
    Run a probe container with the sandbox's flags and network and verify,
    empirically:
      • the LLM gateway and mock services are reachable,
      • the gateway refuses anything but the LLM API,
      • the internet is NOT reachable (no TCP, no DNS).

    The probe runs in the mock-services image: isolation is a property of the
    network, not of the agent image, and an agent image need not contain Python.
    """
    image = _mock_image() or default_image()
    probe = f"probe-{uuid.uuid4().hex[:8]}"
    name = f"{_NAME_PREFIX}-{probe}"
    try:
        proc = _docker(
            ["run", "--rm", "--name", name, *_SANDBOX_FLAGS, *_labels(probe),
             "--entrypoint", "python", image, "-c", _PROBE, PROXY_CONTAINER, MOCK_CONTAINER],
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        _remove_quietly(name)
        return {"ok": False, "error": f"probe failed: {type(e).__name__}: {e}"}
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


# ── World and audit (mock-services, reached through `docker exec`) ────────────

# The mock-services image's own Python, not curl: it is the one tool the image
# cannot lose. The body comes on stdin, so canned responses of any size fit.
_WORLD_INIT = (
    "import sys, urllib.request, urllib.error\n"
    "req = urllib.request.Request(sys.argv[1], data=sys.stdin.buffer.read(), method='POST',\n"
    "                             headers={'Content-Type': 'application/json'})\n"
    "try:\n"
    "    sys.stdout.write(urllib.request.urlopen(req, timeout=10).read().decode())\n"
    "except urllib.error.HTTPError as e:\n"
    "    sys.stderr.write('HTTP %s: %s' % (e.code, e.read().decode(errors='replace')[:500]))\n"
    "    sys.exit(3)\n"
)


def init_world(run_id: str, fixtures: List[str], responses: Optional[Dict[str, Any]]) -> Optional[str]:
    """
    Create the run's world in mock-services, before the agent starts. None means
    it is ready; otherwise why not, which the caller fails closed.

    The agent under test used to do this itself, so an agent that skipped it
    acted in a world without the case's attack fixture and passed vacuously.
    mock-services creates a world once: the bundled agent's own init call, with
    the same fixtures, is then a harmless repeat.
    """
    body: Dict[str, Any] = {"fixtures": fixtures}
    if responses:
        body["responses"] = responses  # the case's `mock_responses`; any other key is a 422
    url = f"http://localhost:{MOCK_PORT}/runs/{quote(run_id, safe='')}/init"
    try:
        proc = _docker(["exec", "-i", MOCK_CONTAINER, "python", "-c", _WORLD_INIT, url],
                       timeout=30, input=json.dumps(body))
    except (OSError, subprocess.TimeoutExpired) as e:
        return f"World init failed: {type(e).__name__}: {e}"
    if proc.returncode != 0:
        return f"World init failed: {_last_line(proc.stderr) or f'exit {proc.returncode}'}"
    try:
        reply = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return f"World init failed: unreadable reply {proc.stdout.strip()[:200]!r}"
    if not isinstance(reply, dict) or reply.get("run") != run_id:
        return f"World init failed: unexpected reply {str(reply)[:200]}"
    if reply.get("created") is False:
        # A fresh run id that already has a world: something else made it, and
        # its audit log is not this run's alone.
        return f"World init failed: a world for run {run_id} already existed."
    if "fixtures" in reply and sorted(map(str, reply["fixtures"])) != sorted(map(str, fixtures)):
        return f"World init failed: mock-services loaded fixtures {reply['fixtures']}, not {fixtures}."
    return None


_AUDIT_FETCH = ("import sys, urllib.request; "
                "sys.stdout.write(urllib.request.urlopen(sys.argv[1], timeout=10).read().decode())")


def _fetch_audit_record(run_id: str) -> Optional[Dict[str, Any]]:
    url = f"http://localhost:{MOCK_PORT}/audit/log?run={quote(run_id, safe='')}"
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
    """
    The run's server-side audit log, read by the HARNESS directly from
    mock-services once the agent container has exited.

    The agent also fetches this log and reports it on stdout, but that copy is
    relayed by the very process under test. Ground truth the subject can edit is
    not ground truth, so the harness's copy replaces it. None = unavailable,
    which the rule layer fails closed.
    """
    record = _fetch_audit_record(run_id)
    return record["entries"] if record else None


# ── Container lifecycle ───────────────────────────────────────────────────────

def _remove_labelled(filters: List[str]) -> int:
    """Force-remove every container matching all `filters`, then such volumes. Returns containers removed."""
    flags = [arg for f in filters for arg in ("--filter", f)]
    removed = 0
    try:
        ps = _docker(["ps", "-aq", *flags], timeout=30)
        ids = ps.stdout.split() if ps.returncode == 0 else []
        if ids:
            rm = _docker(["rm", "-f", *ids], timeout=120)
            removed = len(rm.stdout.split())
        # Input volumes (volume transport) are only removable once no container uses them.
        vols = _docker(["volume", "ls", "-q", *flags], timeout=30)
        names = vols.stdout.split() if vols.returncode == 0 else []
        if names:
            _docker(["volume", "rm", "-f", *names], timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        pass
    return removed


def remove_batch_containers(batch_id: str) -> int:
    """
    Force-remove every container (and input volume) labelled with this batch,
    e.g. after Ctrl-C stopped a batch mid-run. Returns how many containers went.
    """
    if not isinstance(batch_id, str) or not batch_id.strip() or "\n" in batch_id:
        return 0  # an empty value would match far more than one batch
    return _remove_labelled([f"label=creuset.batch={batch_id}"])


def remove_all_test_containers() -> int:
    """Every container the harness started for this project, whatever its batch."""
    # creuset.run is on one-shot containers only, never on the compose services.
    return _remove_labelled([f"label=creuset.project={PROJECT}", "label=creuset.run"])


# ── Core ──────────────────────────────────────────────────────────────────────

@dataclass
class _Run:
    """One case's run: identity, image and settings, for the transcript either way it ends."""

    case_id: str
    variant: str
    batch_id: Optional[str]
    image_ref: str
    run_id: str = ""
    image_id: Optional[str] = None
    harness_config: Optional[Dict[str, str]] = None
    start: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        self.run_id = f"{_name_part(self.case_id)}-{_name_part(self.variant)}-{uuid.uuid4().hex[:8]}"

    @property
    def container(self) -> str:
        return f"{_NAME_PREFIX}-test-{self.run_id}".lower()

    def elapsed(self) -> float:
        return round(time.time() - self.start, 2)

    def harness_fields(self) -> Dict[str, Any]:
        return {"audit_source": "harness", "agent_image": self.image_ref,
                "agent_image_id": self.image_id, "harness_config": self.harness_config}

    def failure(self, status: str, error: str) -> Dict[str, Any]:
        return _failure(self.case_id, self.variant, self.run_id, status, error,
                        time.time() - self.start, **self.harness_fields())


def _failure(case_id: str, variant: str, run_id: str, status: str, error: str, elapsed: float,
             **harness: Any) -> Dict[str, Any]:
    try:
        limit = int(_setting("MAX_LLM_CALLS"))
    except ValueError:
        limit = int(_ENV_DEFAULTS["MAX_LLM_CALLS"])
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
        "llm_calls_limit": limit,
        "budget_ok": False,
        "error": error,
        "elapsed_seconds": round(elapsed, 2),
        **harness,
    }


def run_case(case: Dict[str, Any], variant: str, *, batch_id: Optional[str] = None,
             image: Optional[str] = None) -> Dict[str, Any]:
    """Run one test case in a fresh sandbox container. Always returns a transcript dict."""
    run = _Run(case_id=str(case.get("id") or case.get("test_id") or "CUSTOM"), variant=str(variant),
               batch_id=batch_id, image_ref=(image or default_image()))
    try:
        return _run_case(case, run)
    except Exception as e:  # pylint: disable=broad-except — a case must never vanish
        return run.failure("harness_error", f"{type(e).__name__}: {e}")


def _run_case(case: Dict[str, Any], run: _Run) -> Dict[str, Any]:
    # Callers validate the variant first; this is the last line before it
    # becomes a container name and a run id.
    if not _VARIANT_NAME.fullmatch(run.variant):
        return run.failure("harness_error", f"invalid variant {run.variant!r}")
    env = _container_env(run.run_id)
    # Recorded on every transcript, failures included, so a report can tell
    # whether all of its cases ran under the same settings.
    run.harness_config = {name: env[name] for name in _RECORDED_SETTINGS}
    problems = _config_problems()
    if problems:
        return run.failure("harness_error", " ".join(problems))
    try:
        run.image_ref, run.image_id = resolve_image(run.image_ref)
    except RuntimeError as e:
        return run.failure("container_error", str(e))

    fixtures = list(case.get("fixtures") or [])
    problem = init_world(run.run_id, fixtures, case.get("mock_responses"))
    if problem:
        return run.failure("container_error", problem)

    payload = json.dumps(contract.agent_scenario(case))
    if scenario_transport() == "volume":
        outcome = _run_with_volume(run, env, payload)
    else:
        outcome = _run_with_bind(run, env, payload)
    if isinstance(outcome, dict):
        return outcome  # already a failure transcript
    return _collect(run, outcome)


def _agent_command(run: _Run, env: Dict[str, str], mount: List[str], scenario_file: str) -> List[str]:
    cmd = ["run", "--rm", "--name", run.container, *_SANDBOX_FLAGS, *_labels(run.run_id, run.batch_id)]
    for k, v in env.items():
        cmd += ["-e", f"{k}={v}"]
    # The tail is the agent contract's input: for the bundled image in bind mode,
    # exactly `--scenario-file /scenario.json --variant <variant>`, as always.
    return cmd + [*mount, run.image_id or run.image_ref,
                  "--scenario-file", scenario_file, "--variant", run.variant]


def _execute(run: _Run, cmd: List[str]):
    """The finished container's CompletedProcess, or a timeout failure transcript."""
    try:
        return _docker(cmd, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        _remove_quietly(run.container)
        return run.failure("timeout", f"Container exceeded {TIMEOUT}s and was killed.")
    except BaseException:
        # Ctrl-C while the agent runs: do not leave it running unattended.
        _remove_quietly(run.container)
        raise


def _remove_quietly(container: str) -> None:
    try:
        _docker(["rm", "-f", container], timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _run_with_bind(run: _Run, env: Dict[str, str], payload: str):
    with tempfile.TemporaryDirectory(prefix="creuset-") as tmp:
        scenario_path = Path(tmp) / "scenario.json"
        scenario_path.write_text(payload, encoding="utf-8")
        mount = ["-v", f"{scenario_path.resolve().as_posix()}:/scenario.json:ro"]
        return _execute(run, _agent_command(run, env, mount, "/scenario.json"))


def _run_with_volume(run: _Run, env: Dict[str, str], payload: str):
    volume = f"{_NAME_PREFIX}-in-{run.run_id}".lower()
    try:
        problem = _fill_volume(run, volume, payload)
        if problem:
            return run.failure("container_error", problem)
        mount = ["-v", f"{volume}:/creuset-in:ro"]
        return _execute(run, _agent_command(run, env, mount, "/creuset-in/scenario.json"))
    finally:
        # Also after a timeout or Ctrl-C: the agent container is gone by now
        # (--rm, or removed above), so nothing holds the volume.
        try:
            _docker(["volume", "rm", "-f", volume], timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            pass


_VOLUME_FILL = ("import sys; "
                "open('/creuset-in/scenario.json', 'wb').write(sys.stdin.buffer.read())")


def _fill_volume(run: _Run, volume: str, payload: str) -> Optional[str]:
    """
    Write the scenario into a fresh named volume, through the Docker API alone.

    A bind mount names a path on the machine running this script; a remote or
    nested daemon resolves it on ITS filesystem and mounts an empty directory,
    so every case would fail. Stdin travels with the API call instead.
    """
    image = _mock_image()
    if not image:
        return (f"Volume transport needs the '{MOCK_CONTAINER}' container's image to fill the input "
                f"volume, and it could not be inspected.")
    create = _docker(["volume", "create", *_labels(run.run_id, run.batch_id), volume], timeout=30)
    if create.returncode != 0:
        return f"Could not create input volume {volume}: {_first_line(create.stderr)}"
    helper = f"{_NAME_PREFIX}-input-{run.run_id}".lower()
    # Root inside a no-network, no-capability helper: a fresh volume is owned by
    # root, and the mock image otherwise runs as an unprivileged user. The file
    # comes out world-readable, and the agent mounts the volume read-only.
    cmd = ["run", "--rm", "-i", "--name", helper, *_HELPER_FLAGS, "--user", "0:0",
           *_labels(run.run_id, run.batch_id), "-v", f"{volume}:/creuset-in",
           "--entrypoint", "python", image, "-c", _VOLUME_FILL]
    try:
        proc = _docker(cmd, timeout=60, input=payload)
    except subprocess.TimeoutExpired:
        _remove_quietly(helper)
        return f"Filling input volume {volume} timed out."
    if proc.returncode != 0:
        return f"Could not fill input volume {volume}: {_last_line(proc.stderr) or f'exit {proc.returncode}'}"
    return None


def _collect(run: _Run, proc: subprocess.CompletedProcess) -> Dict[str, Any]:
    """The transcript of a container that ran to the end, judged against the contract."""
    elapsed = run.elapsed()  # the agent's time, before the harness's own audit fetch
    stdout, stderr = (proc.stdout or "").strip(), (proc.stderr or "").strip()
    transcript, why = contract.parse_agent_stdout(stdout)
    if transcript is None:
        status = "container_error" if proc.returncode != 0 else "parse_error"
        return run.failure(status, f"{why} exit={proc.returncode} stderr={stderr[-800:]} stdout={stdout[:300]}")

    override: Optional[Tuple[str, str]] = None
    violations = contract.validate_transcript(transcript)
    if violations:
        override = ("contract_error", "The transcript breaks schemas/transcript.v1.json: "
                    + "; ".join(violations[:20])
                    + (f" (+{len(violations) - 20} more)" if len(violations) > 20 else ""))
    else:
        contradiction = contract.exit_code_problem(transcript, proc.returncode)
        if contradiction:
            override = ("container_error", contradiction + (f". stderr={stderr[-800:]}" if stderr else "."))
    if override and transcript.get("error"):
        override = (override[0], f"{override[1]} (agent error: {str(transcript['error'])[:300]})")

    # The harness, not the agent, is authoritative for identity, for which build
    # ran, and for what the run actually did.
    record = _fetch_audit_record(run.run_id)
    own: Dict[str, Any] = {
        "test_id": run.case_id,
        "run_id": run.run_id,
        "variant": run.variant,
        "elapsed_seconds": elapsed,
        "service_audit": record["entries"] if record else None,
        # The fixtures mock-services actually loaded, to compare with the case's.
        "service_fixtures": record.get("fixtures") if record else None,
        **run.harness_fields(),
    }
    if stderr:
        own["stderr"] = stderr[-2000:]
    result = _harness_view(transcript, own)
    if override:
        result["status"], result["error"] = override
    return result


def _harness_view(transcript: Dict[str, Any], own: Dict[str, Any]) -> Dict[str, Any]:
    """
    The agent's transcript with every harness-owned field replaced by `own`.

    A harness-owned field the harness has no value for this time (say `stderr`)
    is dropped rather than left as the agent wrote it. Fields keep the agent's
    order, so the bundled agent's transcripts read as they always have.
    """
    out: Dict[str, Any] = {}
    for key, value in transcript.items():
        if key in own:
            out[key] = own[key]
        elif key not in contract.HARNESS_OWNED_FIELDS:
            out[key] = value
    for key, value in own.items():
        out.setdefault(key, value)
    return out


def save_transcript(transcript: Dict[str, Any], out_dir: Path = _LOGS_DIR) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    name = f"{_name_part(str(transcript['test_id']))}_{_name_part(str(transcript['variant']))}"
    path = out_dir / f"{name}_{int(time.time() * 1000)}.json"
    path.write_text(json.dumps(transcript, indent=2), encoding="utf-8")
    return path


# ── CLI ───────────────────────────────────────────────────────────────────────

def _library_path(library: Path) -> Path:
    if library.is_file() or library.is_absolute():
        return library
    return _ROOT / library  # repo-relative, as the rest of the project writes them


@app.command()
def main(
    test_id: Optional[str] = typer.Option(None, "--test-id", help="Case ID from attack_library.yaml or benign_tasks.yaml (or --library)"),
    scenario_file: Optional[Path] = typer.Option(None, "--scenario-file", help="A test case as JSON"),
    variant: str = typer.Option("hardened", "--variant", help="Agent variant: naive | hardened | broken, or any name your image understands"),
    save: bool = typer.Option(True, "--save/--no-save", help="Save transcript to logs/"),
    check: bool = typer.Option(False, "--check", help="Only run preflight + isolation probe"),
    image: Optional[str] = typer.Option(None, "--image", help="Agent image to run (default: AGENT_IMAGE, else AGENT_IMAGE_TAG, else creuset-agent:latest)"),
    library: Optional[Path] = typer.Option(None, "--library", help="Look --test-id up in this library instead of the bundled ones"),
    cleanup: Optional[str] = typer.Option(None, "--cleanup", metavar="BATCH_ID|all",
                                          help="Remove the test containers (and input volumes) left by a batch, "
                                               "or by every batch with 'all', then exit. 'all' includes any "
                                               "batch still running."),
) -> None:
    """Run a single test case through the sandbox and print the transcript JSON on stdout."""
    if cleanup is not None:
        removed = remove_all_test_containers() if cleanup == "all" else remove_batch_containers(cleanup)
        console.print(f"[green]✓[/green] Removed {removed} test container(s).")
        raise typer.Exit(code=0)

    problem = validate_variant(variant, image=image)
    if problem:
        console.print(f"[red]✗[/red] {problem}")
        raise typer.Exit(code=2)
    problems = preflight(image)
    if problems:
        for p in problems:
            console.print(f"[red]✗[/red] {p}")
        raise typer.Exit(code=2)
    for warning in [*preflight_warnings(), canary_warning(variant, image=image)]:
        if warning:
            console.print(f"[yellow]![/yellow] {warning}")

    if check:
        probe = isolation_probe()
        console.print_json(json.dumps(probe))
        console.print("[green]✓ Sandbox isolated[/green]" if probe["ok"] else "[red]✗ Isolation check FAILED[/red]")
        raise typer.Exit(code=0 if probe["ok"] else 1)

    if test_id:
        lib = _library_path(library) if library else None
        try:
            case = find_case(test_id, lib)
        except (OSError, ValueError, yaml.YAMLError) as e:
            console.print(f"[red]✗[/red] {e}")
            raise typer.Exit(code=2)
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

    transcript = run_case(case, variant, image=image)

    status = transcript.get("status", "unknown")
    color = "green" if status == "completed" else "red"
    tools = [t.get("tool") if isinstance(t, dict) else "?" for t in (transcript.get("tool_calls") or [])]
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
