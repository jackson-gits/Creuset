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
  2. docker run --rm --name creuset-test-<run_id> --label creuset.run=<run_id> ...
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
  python sandbox/run_test.py --cleanup        # remove containers a crash left behind
"""

from __future__ import annotations

import hashlib
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
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple
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
# Every container the harness starts carries these labels, so whatever a crash,
# a Ctrl-C or a cancelled CI job leaves behind can be found and removed:
# creuset.stack tells two stacks apart (CREUSET_PREFIX), creuset.batch one
# loader's containers from another's. Compose's services carry none of them.
STACK_LABEL = f"creuset.stack={PREFIX}creuset"
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
    """
    The agent under test: an image, the variant label it runs as, and the
    agent's own settings (`env`, never secrets: whatever is passed here is
    readable by a hijacked agent).
    """
    image: str
    variant: str
    bundled: bool
    env: Tuple[Tuple[str, str], ...] = ()

    def args(self) -> List[str]:
        # An external image runs its own ENTRYPOINT/CMD and finds the scenario
        # through CREUSET_SCENARIO_FILE; only the bundled agent takes flags.
        if self.bundled:
            return ["--scenario-file", SCENARIO_MOUNT, "--variant", self.variant]
        return []

    def describe(self) -> Dict[str, Any]:
        described: Dict[str, Any] = {"kind": "bundled" if self.bundled else "external",
                                     "image": self.image, "variant": self.variant}
        if self.env:
            # Names, and a fingerprint of the values: enough to tell two runs'
            # configurations apart without writing the values into every log.
            described["env"] = [name for name, _ in self.env]
            described["env_sha256"] = env_fingerprint(self.env)
        return described


def env_fingerprint(env: Tuple[Tuple[str, str], ...]) -> str:
    return hashlib.sha256(json.dumps(sorted(env), separators=(",", ":")).encode("utf-8")).hexdigest()


def subject_problem(variant: str, agent_image: Optional[str] = None) -> Optional[str]:
    """Why (variant, agent_image) cannot be run, or None."""
    if not agent_image:
        return validate_variant(variant)
    if not _IMAGE_REF.fullmatch(agent_image):
        return f"invalid image reference {agent_image!r}"
    return validate_label(variant)


def make_subject(variant: str, agent_image: Optional[str] = None,
                 env: Tuple[Tuple[str, str], ...] = ()) -> Subject:
    """The subject for (variant, agent_image, env); raises ValueError if it cannot run."""
    problem = subject_problem(variant, agent_image)
    if problem:
        raise ValueError(problem)
    if agent_image:
        return Subject(image=agent_image, variant=variant, bundled=False, env=tuple(env))
    return Subject(image=AGENT_IMAGE, variant=variant, bundled=True, env=tuple(env))


# The environment every test container receives; the subject's own `env` is
# added after it, and may not touch any of these names.
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
        # Anthropic's SDK appends /v1/messages to its base URL itself, so it gets
        # the gateway's root (llm-proxy pointed at api.anthropic.com).
        "ANTHROPIC_BASE_URL": os.getenv("AGENT_ANTHROPIC_BASE", "http://llm-proxy:11434"),
        "ANTHROPIC_API_KEY": "sandbox-placeholder-key",
        # Empty when unset: preflight refuses that for the bundled agent, and an
        # external one may not use a model at all.
        "AGENT_MODEL": os.getenv("AGENT_MODEL", ""),
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


# ── The agent's own settings ──────────────────────────────────────────────────

HARNESS_ENV = frozenset(_container_env("x", "x"))
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


def parse_agent_env(pairs: Sequence[str] = (), env_file: Optional[Path] = None) -> Tuple[Tuple[str, str], ...]:
    """
    The agent's own settings, from an env file (KEY=VALUE lines, # comments)
    and then `KEY=VALUE` pairs, which override the file. Raises ValueError.

    Real agents need their own configuration (a feature flag, a prompt path, a
    region), and the sandbox passes nothing from the host by default. What it
    refuses: a name the harness sets (the contract, the LLM endpoint), the
    CREUSET_ namespace, and values that are not one line.
    """
    merged: Dict[str, str] = {}
    sources: List[Tuple[str, str]] = []
    if env_file is not None:
        for number, line in enumerate(env_file.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "=" not in stripped:
                raise ValueError(f"{env_file}:{number}: expected KEY=VALUE")
            sources.append((stripped.removeprefix("export "), f"{env_file}:{number}"))
    sources.extend((pair, "--agent-env") for pair in pairs)
    for text, where in sources:
        name, sep, value = text.partition("=")
        name = name.strip()
        if not sep:
            raise ValueError(f"{where}: expected KEY=VALUE, not {text!r}")
        if not _ENV_NAME.fullmatch(name):
            raise ValueError(f"{where}: {name!r} is not an environment variable name")
        if name in HARNESS_ENV or name.startswith("CREUSET_"):
            raise ValueError(f"{where}: {name} is set by the harness and cannot be overridden")
        if "\n" in value or "\r" in value or "\0" in value:
            raise ValueError(f"{where}: the value of {name} must be one line")
        merged[name] = value
    return tuple(sorted(merged.items()))


# Agent settings may point into this run's world, which only exists per run:
# `ORDERS_API_URL=${CREUSET_MOCK_URL}/http/orders-api` re-points an agent's
# HTTP client at the REST mock without a code change.
PER_RUN_REFERENCES = ("CREUSET_MOCK_URL", "CREUSET_RUN_ID")


def _per_run(env: Tuple[Tuple[str, str], ...], harness_env: Dict[str, str]) -> List[Tuple[str, str]]:
    """The agent's settings with ${CREUSET_MOCK_URL} / ${CREUSET_RUN_ID} filled in for this run."""
    filled = []
    for name, value in env:
        for ref in PER_RUN_REFERENCES:
            value = value.replace("${" + ref + "}", harness_env[ref])
        filled.append((name, value))
    return filled


# ── Sandbox limits ────────────────────────────────────────────────────────────

_SIZE = re.compile(r"^[1-9][0-9]{0,6}[kmg]?$")
_CPUS = re.compile(r"^(?:[1-9][0-9]?|0)(?:\.[0-9]{1,2})?$")
_TMPFS_DIR = re.compile(r"^(?:/[A-Za-z0-9_.-]+)+$")


@dataclass(frozen=True)
class SandboxLimits:
    """
    The box a test container runs in. The defaults are what every published
    result ran under; real agent images often need more memory, or a writable
    cache directory, and the read-only root filesystem allows only /tmp.
    """
    memory: str = "512m"
    cpus: str = "1.0"
    pids: int = 256
    tmp_size: str = "64m"
    tmpfs: Tuple[str, ...] = ()   # extra writable directories, each its own noexec tmpfs

    def flags(self) -> List[str]:
        mount = f"rw,noexec,nosuid,size={self.tmp_size}"
        flags = ["--network", NETWORK, "--read-only", "--tmpfs", f"/tmp:{mount}"]
        for directory in self.tmpfs:
            flags += ["--tmpfs", f"{directory}:{mount}"]
        return flags + [
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", str(self.pids),
            "--memory", self.memory,
            "--cpus", self.cpus,
            "--no-healthcheck",
        ]

    def describe(self) -> Dict[str, Any]:
        return {"memory": self.memory, "cpus": self.cpus, "pids": self.pids,
                "tmp_size": self.tmp_size, "tmpfs": list(self.tmpfs)}


def limits_from_env(env: Mapping[str, str] = os.environ) -> SandboxLimits:
    """CREUSET_SANDBOX_* as SandboxLimits; raises ValueError naming the bad setting."""
    defaults = SandboxLimits()
    memory = env.get("CREUSET_SANDBOX_MEMORY", "").strip().lower() or defaults.memory
    cpus = env.get("CREUSET_SANDBOX_CPUS", "").strip() or defaults.cpus
    pids = env.get("CREUSET_SANDBOX_PIDS", "").strip() or str(defaults.pids)
    tmp_size = env.get("CREUSET_SANDBOX_TMP_SIZE", "").strip().lower() or defaults.tmp_size
    tmpfs = tuple(d.strip() for d in env.get("CREUSET_SANDBOX_TMPFS", "").split(",") if d.strip())
    if not _SIZE.fullmatch(memory):
        raise ValueError(f"CREUSET_SANDBOX_MEMORY={memory!r}: a size such as 512m or 2g")
    if not _CPUS.fullmatch(cpus) or float(cpus) <= 0:
        raise ValueError(f"CREUSET_SANDBOX_CPUS={cpus!r}: a number of CPUs such as 1.0 or 2")
    if not pids.isdigit() or not 16 <= int(pids) <= 32768:
        raise ValueError(f"CREUSET_SANDBOX_PIDS={pids!r}: a whole number from 16 to 32768")
    if not _SIZE.fullmatch(tmp_size):
        raise ValueError(f"CREUSET_SANDBOX_TMP_SIZE={tmp_size!r}: a size such as 64m")
    for directory in tmpfs:
        if not _TMPFS_DIR.fullmatch(directory) or "/../" in directory + "/" or "/./" in directory + "/":
            raise ValueError(f"CREUSET_SANDBOX_TMPFS: {directory!r} is not an absolute directory path")
        if directory in ("/tmp", SCENARIO_MOUNT):
            raise ValueError(f"CREUSET_SANDBOX_TMPFS: {directory} is already mounted by the harness")
    return SandboxLimits(memory=memory, cpus=cpus, pids=int(pids), tmp_size=tmp_size, tmpfs=tmpfs)


def _sandbox_flags() -> List[str]:
    return limits_from_env().flags()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _docker(args: List[str], timeout: int = 60, input: Optional[str] = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout,
        encoding="utf-8", errors="replace", input=input,
    )


def _labels(run_id: Optional[str] = None, batch_id: Optional[str] = None) -> List[str]:
    out = ["--label", STACK_LABEL]
    if run_id:
        out += ["--label", f"creuset.run={run_id}"]
    if batch_id:
        out += ["--label", f"creuset.batch={batch_id}"]
    return out


_BATCH_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def remove_containers(batch_id: Optional[str] = None) -> int:
    """
    Force-remove the containers the harness started: one batch's, or with no
    batch every one on this stack. Removing an agent's container also ends the
    `docker run` waiting on it, so a stopped batch's workers return at once.
    Returns how many went.
    """
    filters = ["--filter", f"label={STACK_LABEL}"]
    if batch_id is not None:
        if not _BATCH_ID.fullmatch(batch_id):
            return 0   # an empty or odd value must never widen the filter
        filters += ["--filter", f"label=creuset.batch={batch_id}"]
    try:
        listed = _docker(["ps", "-aq", *filters], timeout=30)
        ids = listed.stdout.split() if listed.returncode == 0 else []
        if not ids:
            return 0
        removed = _docker(["rm", "-f", *ids], timeout=120)
        return len(removed.stdout.split())
    except (OSError, subprocess.TimeoutExpired):
        return 0


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


_platform_cache: List[Optional[str]] = []


def _server_platform() -> Optional[str]:
    """The daemon's os/arch (linux/amd64), asked once per process."""
    if not _platform_cache:
        try:
            proc = _docker(["version", "--format", "{{.Server.Os}}/{{.Server.Arch}}"], timeout=20)
            value = proc.stdout.strip() if proc.returncode == 0 else ""
        except (OSError, subprocess.TimeoutExpired):
            value = ""
        _platform_cache.append(value if re.fullmatch(r"[a-z0-9]+/[a-z0-9_]+", value) else None)
    return _platform_cache[0]


def image_content(image: str) -> Optional[str]:
    """
    What `image` IS, as opposed to which build produced it.

    Docker's containerd image store wraps every build in a new index (its build
    attestation carries a timestamp), so rebuilding unchanged code gives a new
    image ID. Comparing IDs then calls identical bytes "a different build". The
    platform-specific image ID is the digest of the image config and its layers:
    stable across identical rebuilds, different the moment anything changes, and
    what Compose itself records (com.docker.compose.image). Without --platform
    support (an older Docker), the plain ID, which on the classic store is
    already that digest.
    """
    platform = _server_platform()
    if platform:
        try:
            proc = _docker(["image", "inspect", "--platform", platform, image, "--format", "{{.Id}}"],
                           timeout=30)
            ident = proc.stdout.strip()
            if proc.returncode == 0 and ident:
                return ident
        except (OSError, subprocess.TimeoutExpired):
            pass
    return image_id(image)


# ── Was the bundled image built from these files? ─────────────────────────────

_AGENT_DIR = _ROOT / "agent"
# What the bundled agent's behaviour is made of, relative to agent/ — and to
# /app inside the image, where agent/Dockerfile copies the directory.
_AGENT_SOURCES = ("*.py", "variants/*.txt", "requirements.txt", "constraints.txt")
# Prints {path: sha256 or null} for the image's own copies of argv's paths.
AGENT_DIGEST_SCRIPT = (
    "import hashlib, json, sys\n"
    "out = {}\n"
    "for p in sys.argv[1:]:\n"
    "    try:\n"
    "        out[p] = hashlib.sha256(open('/app/' + p, 'rb').read()).hexdigest()\n"
    "    except OSError:\n"
    "        out[p] = None\n"
    "print(json.dumps(out))\n"
)
_source_checks: Dict[Tuple[str, str], Optional[str]] = {}


def agent_sources(agent_dir: Path = _AGENT_DIR) -> Dict[str, str]:
    """sha256 of each file the bundled image runs, by POSIX path relative to agent/."""
    found: Dict[str, str] = {}
    for pattern in _AGENT_SOURCES:
        for path in sorted(agent_dir.glob(pattern)):
            if path.is_file():
                # Raw bytes on both sides: the image is built from these very
                # bytes, CRLF checkout or not.
                found[path.relative_to(agent_dir).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return found


def source_drift(host: Mapping[str, str], image: Mapping[str, Optional[str]]) -> List[str]:
    """What differs between the host's agent/ files and the image's copies, one line per file."""
    drift = []
    for path, digest in sorted(host.items()):
        theirs = image.get(path)
        if theirs is None:
            drift.append(f"agent/{path} is not in the image (added since it was built)")
        elif theirs != digest:
            drift.append(f"agent/{path} differs from the image's copy")
    return drift


def stale_image_problem(image: str) -> Optional[str]:
    """
    Why the bundled image cannot stand for agent/ as it is on disk, or None.

    Prompts and agent code are baked in at build time. Edit a variant without
    rebuilding and the container runs the OLD prompt while every record names
    the new one; the image's age says little (a checkout touches mtimes, and a
    rebuild of unchanged code is harmless), so the bytes are compared instead.
    Cached per (image, sources) for the life of the process.
    """
    if os.getenv("CREUSET_ALLOW_STALE_AGENT") == "1":
        return None
    ident = image_id(image)
    if ident is None:
        return None  # preflight reports the missing image itself
    host = agent_sources()
    key = (ident, hashlib.sha256(json.dumps(host, sort_keys=True).encode("utf-8")).hexdigest())
    if key not in _source_checks:
        _source_checks[key] = _check_sources(image, ident, host)
    return _source_checks[key]


def _check_sources(image: str, ident: str, host: Dict[str, str]) -> Optional[str]:
    name = f"creuset-check-{uuid.uuid4().hex[:8]}"
    cmd = ["run", "--rm", "--name", name, *_labels(), "--network", "none", "--read-only", "--cap-drop", "ALL",
           "--security-opt", "no-new-privileges", "--no-healthcheck",
           "--entrypoint", "python", ident, "-c", AGENT_DIGEST_SCRIPT, *host]
    try:
        proc = _docker(cmd, timeout=60)
        theirs = json.loads(proc.stdout.strip().splitlines()[-1]) if proc.returncode == 0 else None
    except subprocess.TimeoutExpired:
        _docker(["rm", "-f", name], timeout=30)
        theirs = None
    except (OSError, ValueError, IndexError):
        theirs = None
    if not isinstance(theirs, dict):
        return (f"Could not read the agent's files from image '{image}' to check it was built from "
                f"agent/ as it is now. Rebuild it: docker compose build agent-blue")
    drift = source_drift(host, theirs)
    if not drift:
        return None
    more = f" (and {len(drift) - 3} more)" if len(drift) > 3 else ""
    return (f"Image '{image}' was not built from agent/ as it is now: {'; '.join(drift[:3])}{more}. "
            f"It would run the old code while every record names the new. "
            f"Rebuild it: docker compose build agent-blue "
            f"(or set CREUSET_ALLOW_STALE_AGENT=1 to run an older build on purpose).")


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
        "agent_image_content": image_content(image_ref) if image_ref else None,
        **extra,
    }


# ── Preflight ─────────────────────────────────────────────────────────────────

def preflight(subject: Optional[Subject] = None) -> List[str]:
    """Return a list of problems that make sandbox runs impossible (empty = ready)."""
    problems: List[str] = []
    try:
        limits_from_env()
    except ValueError as e:
        problems.append(str(e))
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

    bundled = subject is None or subject.bundled
    if bundled and not os.getenv("AGENT_MODEL"):
        # The bundled agent would ask for gpt-4o-mini, which a non-OpenAI
        # upstream refuses on every case: a whole batch failing closed.
        problems.append("AGENT_MODEL is not set — put it in .env (e.g. AGENT_MODEL=openai/gpt-oss-20b)")
    image = subject.image if subject else AGENT_IMAGE
    if image_id(image) is None:
        hint = "docker compose build agent-blue" if bundled else f"docker pull {image}"
        problems.append(f"Agent image '{image}' missing — run: {hint}")
    elif bundled:
        stale = stale_image_problem(image)
        if stale:
            problems.append(stale)
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
    inspect = _docker(["inspect", MOCK_CONTAINER, "--format", "{{.Config.Image}}"])
    probe_image = inspect.stdout.strip()
    if inspect.returncode != 0 or not probe_image:
        return {"ok": False, "error": f"container '{MOCK_CONTAINER}' not found; start the infrastructure first"}
    proc = _docker(
        ["run", "--rm", *_labels(), *_sandbox_flags(), "--entrypoint", "python", probe_image, "-c", _PROBE],
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


def init_world(run_id: str, fixtures: List[str], responses: Optional[Dict[str, Any]] = None,
               http_responses: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """
    Create the run's world before the agent starts. Returns why it failed, or None.

    mock-services creates a world once and never resets it, so the bundled
    agent's own init call afterwards (same fixtures) is a harmless repeat. The
    body goes over stdin: canned responses can be far larger than a Windows
    command line.
    """
    url = f"http://localhost:8001/runs/{quote(run_id, safe='')}/init"
    world: Dict[str, Any] = {"fixtures": list(fixtures), "responses": responses or {}}
    if http_responses:   # only when used: an older mock-services image refuses the key
        world["http_responses"] = http_responses
    body = json.dumps(world)
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

def run_case(case: Dict[str, Any], variant: str, subject: Optional[Subject] = None,
             batch_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Run one test case in a fresh sandbox container. Always returns a transcript
    dict; anything that goes wrong is a non-"completed" status (fail-closed).

    `subject` defaults to the bundled agent at `variant`. `batch_id` labels the
    container, so the batch can remove it if it is stopped mid-run.
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

    problem = init_world(run_id, fixtures, case.get("tool_responses"), case.get("http_responses"))
    if problem:
        return _failure(case_id, subject, run_id, "harness_error",
                        f"Could not create the run's mock world: {problem}", time.time() - setup_start,
                        image_ref)

    try:
        flags = _sandbox_flags()
    except ValueError as e:
        return _failure(case_id, subject, run_id, "harness_error", f"Sandbox limits: {e}",
                        time.time() - setup_start, image_ref)

    start = time.time()  # elapsed_seconds is the container's wall time, not the setup's

    with tempfile.TemporaryDirectory(prefix="creuset-") as tmp:
        scenario_path = Path(tmp) / "scenario.json"
        # Only what the agent may read: never the answer key (expected_behavior,
        # forbidden_tools, patterns...), which an agent could otherwise read.
        scenario_path.write_text(json.dumps(agent_scenario(case)), encoding="utf-8")

        cmd = ["run", "--rm", "--name", container, *_labels(run_id, batch_id), *flags]
        # The harness's variables, then the agent's own settings, which
        # parse_agent_env() has already kept off every name the harness sets.
        harness_env = _container_env(run_id, subject.variant)
        for k, v in [*harness_env.items(), *_per_run(subject.env, harness_env)]:
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
        "agent_image_content": image_content(image_ref),
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
    agent_env: Optional[List[str]] = typer.Option(None, "--agent-env", metavar="KEY=VALUE",
                                                  help="A setting for the agent's container (repeatable). Never a secret."),
    agent_env_file: Optional[Path] = typer.Option(None, "--agent-env-file", envvar="CREUSET_AGENT_ENV_FILE",
                                                  help="KEY=VALUE lines for the agent's container. Never secrets."),
    save: bool = typer.Option(True, "--save/--no-save", help="Save transcript to logs/"),
    check: bool = typer.Option(False, "--check", help="Only run preflight + isolation probe"),
    cleanup: bool = typer.Option(False, "--cleanup", help="Remove every container the harness started on this "
                                                          "stack (left behind by a crash), then exit."),
) -> None:
    """Run a single test case through the sandbox and print the transcript JSON on stdout."""
    if cleanup:
        removed = remove_containers()
        console.print(f"[green]✓[/green] Removed {removed} leftover harness container(s).")
        raise typer.Exit(code=0)
    try:
        subject = make_subject(variant, agent_image, parse_agent_env(agent_env or (), agent_env_file))
    except (OSError, ValueError) as e:
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
