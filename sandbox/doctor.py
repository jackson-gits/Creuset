"""
sandbox/doctor.py
──────────────────
Preflight for a whole Creuset setup: is everything a run needs in place, BEFORE
a batch spends an hour and a day's quota finding out?

The common first-run failures are all fail-closed, which is right and
unhelpful: a placeholder key, a wrong model or path, a corporate CA, an old
Compose, a stale image each turn a 26-case run into 26 identical FAILs. Others
are quieter: an unwritable logs/live_traffic leaves the monitor watching an
empty directory, and a prompt without a canary makes the canary check pass
without being able to see a leak. The doctor turns each into one line saying
what is wrong and what to change.

Checks (no call to any LLM provider, no quota):
  Python >= 3.11 and the host packages; .env present; LLM_API_KEY set and not a
  placeholder; AGENT_MODEL set; the judge's settings (model_judge.check_config);
  AGENT_API_BASE shaped the way llm-proxy forwards it; Docker reachable (with
  its own error line); Compose >= 2.24; ports 8081/8090 free; the infra
  preflight and isolation probe from sandbox/run_test.py; llm-proxy running with
  this .env's key; logs/live_traffic writable by the slots' uid (CREUSET_UID,
  default 10001); each variant's prompt matching the image and carrying a canary.

--llm adds two max_tokens=1 calls, a few tokens of quota:
  the agent's route  from a throwaway container on the sandbox network, in the
                     mock-services image (so it works whatever the agent image
                     is), through llm-proxy, exactly as an agent calls it;
  the judge's route  from this machine to JUDGE_API_BASE, as the judge calls it
                     (skip it with --no-judge-call).
  401, 403, 404, 429, 502 and TLS failures each get their own advice.

Exit codes:
  0  ready (warnings allowed, unless --strict)
  2  a configuration problem: fix it before running anything
  3  the configuration looks right, but the provider is unreachable or its
     quota is exhausted

No key is ever printed: every line is redacted against the configured keys.

Usage:
  python sandbox/doctor.py
  python sandbox/doctor.py --llm
  python sandbox/doctor.py --skip-model-judge            # rule-only use
  python sandbox/doctor.py --image acme/agent:1.4 --variant prod --json
"""

from __future__ import annotations

import sys

# Checked before anything else is imported: the modules below use syntax and
# library features an older interpreter would fail on with a traceback that
# never mentions the version.
MIN_PYTHON = (3, 11)
if sys.version_info[:2] < MIN_PYTHON:
    sys.stderr.write(f"Creuset needs Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or later; this is "
                     f"{sys.version.split()[0]}. Create the venv with a newer Python "
                     f"(python3.11 -m venv .venv).\n")
    sys.exit(2)

import importlib  # noqa: E402
import importlib.util  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import re  # noqa: E402
import socket  # noqa: E402
import subprocess  # noqa: E402
import urllib.request  # noqa: E402
import uuid  # noqa: E402
from dataclasses import asdict, dataclass, field  # noqa: E402
from pathlib import Path  # noqa: E402
from types import ModuleType  # noqa: E402
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple  # noqa: E402
from urllib.parse import urlsplit  # noqa: E402

_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

try:
    import typer
    from dotenv import dotenv_values
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text

    # Read-only use: its preflight, isolation probe, variant checks and names.
    # Importing it also loads .env into the environment, as every CLI here does.
    import run_test
except ImportError as _missing:  # pragma: no cover - exercised only on a broken install
    sys.stderr.write(f"Creuset doctor: the Python package '{_missing.name}' is missing. Install the host "
                     f"requirements first: pip install -r requirements.txt\n")
    sys.exit(2)


_ROOT = Path(__file__).resolve().parent.parent

OK, WARN, FAIL, SKIP = "ok", "warn", "fail", "skip"
CONFIG, PROVIDER = "config", "provider"  # what a FAIL means for the exit code

EXIT_OK, EXIT_CONFIG, EXIT_PROVIDER = 0, 2, 3

MIN_COMPOSE = (2, 24)  # `env_file: {path, required: false}` in docker-compose.yml
DEFAULT_SLOT_ID = "10001"  # agent/Dockerfile's user; compose's ${CREUSET_UID:-10001}
DEFAULT_ROUTER_PORT = 8081
UI_PORT = 8090
DEFAULT_UPSTREAM = "api.groq.com"  # docker-compose.yml's ${LLM_UPSTREAM_HOST:-api.groq.com}
MOCK_IMAGE_TAG = "creuset-mock-services:latest"
ROUTER_CONTAINER = "creuset-router"
PROXY_PORT = 11434
# Every container the doctor starts is <prefix>-<hex>, removed afterwards.
_HELPER_PREFIX = "creuset-doctor"
_LLM_TIMEOUT = 60  # seconds for one max_tokens=1 call; the proxy itself waits 120
_DOCKER_TIMEOUT = 30

# Placeholders that have shipped in this repo's templates and CI, plus the
# generic ones. A key equal to one of these is printed (it is public text); a
# real key never is.
_PLACEHOLDER_KEYS = frozenset({
    "your-key-here", "ci-placeholder", "sandbox-placeholder-key", "sk-your-key-here", "dummy-key",
    "your-api-key", "your_api_key", "<your-key>", "changeme", "change-me", "placeholder", "unused",
    "none", "null", "xxx", "test", "key",
})
_PLACEHOLDER_HINT = re.compile(r"your[-_ ]?(api[-_ ]?)?key|placeholder|change[-_ ]?me|dummy", re.I)
# Characters 05-creuset-validate.envsh refuses in the key (nginx would cut or expand them).
_BAD_KEY_CHARS = re.compile(r'[\s"\\$\x00-\x1f\x7f]')

# Provider error bodies and docker output can echo credentials or account ids
# (Groq's 429 names the organisation; OpenAI's 401 shows part of the key).
_KEY_VARS = ("LLM_API_KEY", "JUDGE_API_KEY", "OPENAI_API_KEY")
_SECRET_PATTERNS = (
    (re.compile(r"(?<![A-Za-z0-9])org_[A-Za-z0-9]+"), "org_REDACTED"),
    (re.compile(r"(?<![A-Za-z0-9])gsk_[A-Za-z0-9]+"), "gsk_REDACTED"),
    (re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_*-]{16,}"), "sk-REDACTED"),
)

# Host packages from requirements.txt, by import name. The core ones every run
# imports; the rest serve one tool each, so a missing one is only a warning.
_CORE_PACKAGES = ("openai", "yaml", "jsonschema", "typer", "rich", "dotenv")
_OPTIONAL_PACKAGES = {"fastapi": "the results browser and the router", "uvicorn": "the results browser",
                      "tabulate": "evaluate/run_eval.py"}


# ── Results ───────────────────────────────────────────────────────────────────

@dataclass
class Check:
    """One line of the report. `kind` says what a FAIL means for the exit code."""

    name: str
    status: str
    detail: str
    fix: Optional[str] = None
    kind: Optional[str] = None


def ok(name: str, detail: str) -> Check:
    return Check(name, OK, detail)


def warn(name: str, detail: str, fix: Optional[str] = None) -> Check:
    return Check(name, WARN, detail, fix)


def fail(name: str, detail: str, fix: Optional[str] = None, kind: str = CONFIG) -> Check:
    return Check(name, FAIL, detail, fix, kind)


def skip(name: str, detail: str) -> Check:
    return Check(name, SKIP, detail)


@dataclass
class Context:
    """What the checks look at, and what earlier checks found out for later ones."""

    env: Mapping[str, str]
    dotenv: Mapping[str, Optional[str]] = field(default_factory=dict)
    root: Path = _ROOT
    image: Optional[str] = None
    variants: List[str] = field(default_factory=list)
    llm: bool = False
    judge: bool = True
    judge_call: bool = True
    # Filled in as the checks run.
    docker_ok: bool = False
    infra_ok: bool = False
    image_id: Optional[str] = None
    judge_ok: bool = False
    mock_image: Optional[str] = None  # "" = looked for and not found


def exit_code(checks: List[Check], strict: bool = False) -> int:
    """2 for any configuration problem (or warning, with --strict), else 3 for a provider one, else 0."""
    if any(c.status == FAIL and c.kind != PROVIDER for c in checks):
        return EXIT_CONFIG
    if strict and any(c.status == WARN for c in checks):
        return EXIT_CONFIG
    if any(c.status == FAIL for c in checks):
        return EXIT_PROVIDER
    return EXIT_OK


# ── Small helpers ─────────────────────────────────────────────────────────────

def _run(cmd: List[str], timeout: int = _DOCKER_TIMEOUT, input: Optional[str] = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          encoding="utf-8", errors="replace", input=input)


def _docker(args: List[str], timeout: int = _DOCKER_TIMEOUT) -> subprocess.CompletedProcess:
    return _run(["docker", *args], timeout=timeout)


def _first_line(text: Optional[str]) -> str:
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    # The daemon's own warnings (bridge-nf-call-iptables...) are not why it failed.
    useful = [ln for ln in lines if not ln.upper().startswith("WARNING")]
    return (useful or lines or [""])[0][:300]


def _last_line(text: Optional[str], limit: Optional[int] = 300) -> str:
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    return (lines[-1][:limit] if limit else lines[-1]) if lines else ""


def _helper_name() -> str:
    return f"{_HELPER_PREFIX}-{uuid.uuid4().hex[:10]}"


def _helper_labels(name: str) -> List[str]:
    # The harness's own labels, so `run_test.py --cleanup all` also finds a
    # doctor container a crash left behind.
    project = getattr(run_test, "PROJECT", None) or "creuset"
    return ["--label", f"creuset.project={project}", "--label", f"creuset.run={name}"]


def _remove_quietly(name: str) -> None:
    try:
        _docker(["rm", "-f", name], timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _network() -> str:
    return getattr(run_test, "NETWORK", None) or "creuset-net"


def _mock_container() -> str:
    return getattr(run_test, "MOCK_CONTAINER", None) or "mock-services"


def _proxy_container() -> str:
    return getattr(run_test, "PROXY_CONTAINER", None) or "llm-proxy"


def _default_image(env: Mapping[str, str]) -> str:
    fn = getattr(run_test, "default_image", None)
    if callable(fn):
        return fn()
    return env.get("AGENT_IMAGE") or env.get("AGENT_IMAGE_TAG") or "creuset-agent:latest"


def _bundled_ref(env: Mapping[str, str]) -> str:
    fn = getattr(run_test, "bundled_image_ref", None)
    if callable(fn):
        return fn()
    return env.get("AGENT_IMAGE_TAG") or "creuset-agent:latest"


def _upstream_host(env: Mapping[str, str]) -> str:
    return (env.get("LLM_UPSTREAM_HOST") or "").strip() or DEFAULT_UPSTREAM


def _agent_base(env: Mapping[str, str]) -> str:
    # The same rule as run_test._container_env: what an agent container is given.
    return (env.get("AGENT_API_BASE") or "").strip() or f"http://{_proxy_container()}:{PROXY_PORT}/openai/v1"


def _source(ctx: Context, name: str) -> str:
    """Where a setting's effective value came from, for messages."""
    in_file = ctx.dotenv.get(name)
    if in_file is None:
        return "the environment"
    if in_file == (ctx.env.get(name) or ""):
        return ".env"
    return "the environment, which overrides .env"


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def make_redactor(env: Mapping[str, str]) -> Callable[[str], str]:
    """Scrubs every configured key value, and anything shaped like a key or account id."""
    values = set()
    for source in (env, os.environ):
        for var in _KEY_VARS:
            value = (source.get(var) or "").strip()
            # Shorter values would shred ordinary words; known placeholders are
            # public text, and naming them is the point of the LLM_API_KEY check.
            if len(value) >= 8 and value.lower() not in _PLACEHOLDER_KEYS:
                values.add(value)
    ordered = sorted(values, key=len, reverse=True)

    def redact(text: str) -> str:
        for value in ordered:
            text = text.replace(value, "[REDACTED]")
        for pattern, replacement in _SECRET_PATTERNS:
            text = pattern.sub(replacement, text)
        return text

    return redact


def _model_judge() -> ModuleType:
    """judge/model_judge.py, imported on first use: rule-only setups never need it."""
    judge_dir = str(_ROOT / "judge")
    if judge_dir not in sys.path:
        sys.path.append(judge_dir)
    return importlib.import_module("model_judge")


# ── Configuration (no Docker, no network) ─────────────────────────────────────

def _python_version() -> Tuple[int, int, int]:
    return tuple(sys.version_info[:3])  # type: ignore[return-value]


def check_python(ctx: Context) -> List[Check]:
    found = ".".join(map(str, _python_version()))
    if _python_version()[:2] < MIN_PYTHON:
        return [fail("python", f"Python {found}; Creuset needs 3.11 or later.",
                     fix="Recreate the venv with a newer Python: python3.11 -m venv .venv")]
    missing = [name for name in _CORE_PACKAGES if importlib.util.find_spec(name) is None]
    if missing:
        return [fail("python", f"Python {found}, but host packages are missing: {', '.join(missing)}.",
                     fix="pip install -r requirements.txt (inside the venv)")]
    out = [ok("python", f"Python {found}; host packages installed")]
    for name, used_by in _OPTIONAL_PACKAGES.items():
        if importlib.util.find_spec(name) is None:
            out.append(warn("python", f"The package '{name}' is missing; {used_by} need(s) it.",
                            fix="pip install -r requirements.txt (inside the venv)"))
    return out


def check_env_file(ctx: Context) -> List[Check]:
    path = ctx.root / ".env"
    if path.is_file():
        return [ok(".env", f"found ({_rel(path, ctx.root)})")]
    if (ctx.env.get("LLM_API_KEY") or "").strip():
        return [warn(".env", "No .env file: every setting comes from the process environment.",
                     fix="Fine for CI, as long as the same variables are set wherever `docker compose` runs; "
                         "otherwise copy .env.example to .env.")]
    return [fail(".env", "No .env file, and LLM_API_KEY is not in the environment either.",
                 fix="Copy .env.example to .env (cp .env.example .env), then set LLM_API_KEY, AGENT_MODEL and "
                     "the JUDGE_* settings in it.")]


def _key_provider_mismatch(key: str, host: str) -> Optional[str]:
    host = host.lower()
    groq = host == "groq.com" or host.endswith(".groq.com")
    if groq and not key.startswith("gsk_"):
        return f"LLM_UPSTREAM_HOST is {host}, but Groq keys start with gsk_ and this one does not."
    if key.startswith("gsk_") and not groq:
        return f"LLM_API_KEY looks like a Groq key (gsk_...), but LLM_UPSTREAM_HOST is {host}."
    if key.startswith("sk-or-") and not host.endswith("openrouter.ai"):
        return f"LLM_API_KEY looks like an OpenRouter key (sk-or-...), but LLM_UPSTREAM_HOST is {host}."
    if host == "api.openai.com" and not key.startswith("sk-"):
        return "LLM_UPSTREAM_HOST is api.openai.com, but OpenAI keys start with sk- and this one does not."
    return None


def check_llm_key(ctx: Context) -> List[Check]:
    name = "LLM_API_KEY"
    raw = ctx.env.get("LLM_API_KEY") or ""
    key = raw.strip()
    if not key:
        return [fail(name, "LLM_API_KEY is not set. llm-proxy cannot start without it, and Compose refuses "
                           "the whole file (`set LLM_API_KEY in .env`).",
                     fix="Set LLM_API_KEY=<your provider's API key> in .env.")]
    where = _source(ctx, "LLM_API_KEY")
    keyless_gateway = (ctx.env.get("LLM_UPSTREAM_SCHEME") or "").strip().lower() == "http"
    placeholder = key.lower() in _PLACEHOLDER_KEYS or _PLACEHOLDER_HINT.search(key)
    if placeholder and keyless_gateway:
        # Compose requires a non-empty value even for a keyless local gateway.
        return [ok(name, f"a placeholder (from {where}), sent to the plain-http gateway "
                         f"{_upstream_host(ctx.env)}; fine if it needs no key")]
    if key.lower() in _PLACEHOLDER_KEYS:
        return [fail(name, f"LLM_API_KEY is still the placeholder '{key}' (from {where}). Every agent call "
                           f"would be refused (401) and every case would fail closed.",
                     fix=f"Put your provider's API key in {where.split(',')[0]}: LLM_API_KEY=... "
                         f"(a Groq key starts with gsk_).")]
    if placeholder:
        return [fail(name, f"LLM_API_KEY looks like a placeholder, not a key (from {where}; not shown).",
                     fix="Put your provider's real API key in .env: LLM_API_KEY=...")]
    # The raw value: compose hands it to llm-proxy as is, surrounding spaces included.
    if _BAD_KEY_CHARS.search(raw):
        return [fail(name, "LLM_API_KEY contains whitespace, a quote, a backslash, '$' or a control "
                           "character. llm-proxy refuses to start with it.",
                     fix="Paste the bare key into .env, with no quotes or spaces around it.")]
    out = [ok(name, f"set (from {where}; value not shown)")]
    mismatch = _key_provider_mismatch(key, _upstream_host(ctx.env))
    if mismatch:
        out.append(warn(name, mismatch, fix="Use the key the provider at LLM_UPSTREAM_HOST issued, or point "
                                            "LLM_UPSTREAM_HOST at the key's provider."))
    return out


def check_agent_settings(ctx: Context) -> List[Check]:
    model = (ctx.env.get("AGENT_MODEL") or "").strip()
    if model:
        out = [ok("AGENT_MODEL", model)]
    else:
        out = [fail("AGENT_MODEL", "AGENT_MODEL is not set. The harness has no default model, and Compose "
                                   "refuses the whole file without it (`set AGENT_MODEL in .env`).",
                    fix="Set it in .env to a model LLM_UPSTREAM_HOST serves, e.g. AGENT_MODEL=openai/gpt-oss-20b "
                        "(the published results' model, on Groq).")]
    warnings = getattr(run_test, "preflight_warnings", None)
    for text in (warnings() if callable(warnings) else []):
        out.append(warn("agent settings", text))
    return out


def check_agent_route(ctx: Context) -> List[Check]:
    """AGENT_API_BASE against what llm-proxy forwards, before any call is made."""
    name = "agent route"
    base = _agent_base(ctx.env)
    parts = urlsplit(base)
    host = (parts.hostname or "").lower()
    path = parts.path.rstrip("/")
    proxies = {_proxy_container().lower(), "llm-proxy"}
    if parts.scheme not in ("http", "https") or not host:
        return [fail(name, f"AGENT_API_BASE={base!r} is not an http(s) URL.",
                     fix=f"Leave it unset, or e.g. AGENT_API_BASE=http://llm-proxy:{PROXY_PORT}/openai/v1")]
    if host not in proxies:
        return [warn(name, f"AGENT_API_BASE points at {host}, not llm-proxy. Agent containers sit on an "
                           f"internal network and reach only containers on it.",
                     fix=f"Leave AGENT_API_BASE unset (http://llm-proxy:{PROXY_PORT}/openai/v1) unless {host} "
                         f"is a gateway you attached to that network yourself.")]
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        port = None
    if port != PROXY_PORT or parts.scheme != "http":
        return [fail(name, f"AGENT_API_BASE={base} does not match llm-proxy, which listens on plain http, "
                           f"port {PROXY_PORT}.",
                     fix=f"AGENT_API_BASE=http://llm-proxy:{PROXY_PORT}/openai/v1 (or .../v1)")]
    if path not in ("/v1", "/openai/v1"):
        return [fail(name, f"AGENT_API_BASE ends in {path or '/'}, but llm-proxy forwards only "
                           f"/v1/<endpoint> and /openai/v1/<endpoint>: every agent call would get 403.",
                     fix=f"AGENT_API_BASE=http://llm-proxy:{PROXY_PORT}/openai/v1 for Groq, .../v1 for OpenAI "
                         f"and most others. A provider under a sub-path takes LLM_UPSTREAM_PATH_PREFIX.")]
    upstream = _upstream_host(ctx.env)
    prefix = (ctx.env.get("LLM_UPSTREAM_PATH_PREFIX") or "").strip()
    groq = upstream == "groq.com" or upstream.endswith(".groq.com")
    if not prefix and groq and path == "/v1":
        return [warn(name, f"Groq serves its API under /openai/v1, but AGENT_API_BASE ends in /v1, so "
                           f"{upstream} would answer 404.",
                     fix=f"AGENT_API_BASE=http://llm-proxy:{PROXY_PORT}/openai/v1")]
    if not prefix and upstream == "api.openai.com" and path == "/openai/v1":
        return [warn(name, "OpenAI serves its API under /v1, but AGENT_API_BASE ends in /openai/v1 "
                           "(the Groq default), so api.openai.com would answer 404.",
                     fix=f"AGENT_API_BASE=http://llm-proxy:{PROXY_PORT}/v1")]
    return [ok(name, f"{base} -> llm-proxy -> {upstream}{prefix}")]


def check_judge_config(ctx: Context) -> List[Check]:
    name = "judge"
    if not ctx.judge:
        return [skip(name, "--skip-model-judge: the LLM judge is not used, so its settings are not checked.")]
    try:
        judge = _model_judge()
        judge.check_config()
    except ImportError as e:
        return [fail(name, f"judge/model_judge.py cannot be imported: {e}",
                     fix="pip install -r requirements.txt (inside the venv)")]
    except Exception as e:  # pylint: disable=broad-except — JudgeConfigError and anything like it
        return [fail(name, str(e), fix="Set JUDGE_MODEL and JUDGE_API_BASE in .env (see .env.example), "
                                       "or score rule-only with --skip-model-judge.")]
    ctx.judge_ok = True
    host = urlsplit((ctx.env.get("JUDGE_API_BASE") or "").strip()).hostname or "?"
    return [ok(name, f"{getattr(judge, 'JUDGE_MODEL', '?')} at {host}")]


# ── Docker ────────────────────────────────────────────────────────────────────

def _docker_start_hint(error: str) -> str:
    low = error.lower()
    if "permission denied" in low:
        return ("Your user may not use the Docker socket: add it to the docker group "
                "(sudo usermod -aG docker $USER, then log in again), or use rootless Docker.")
    if sys.platform in ("win32", "darwin"):
        return ("Start Docker Desktop and wait until it reports it is running. If it is, check "
                "`docker context ls` and DOCKER_HOST.")
    return ("Start the daemon (sudo systemctl start docker), or Docker Desktop. If it is running, check "
            "`docker context ls` and DOCKER_HOST.")


def _is_podman() -> bool:
    for args in (["--version"], ["version", "--format", "{{range .Server.Components}}{{.Name}} {{end}}"]):
        try:
            proc = _docker(args, timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if "podman" in f"{proc.stdout} {proc.stderr}".lower():
            return True
    return False


def check_docker(ctx: Context) -> List[Check]:
    name = "docker"
    try:
        proc = _docker(["info", "--format", "{{.ServerVersion}}"], timeout=20)
    except FileNotFoundError:
        return [fail(name, "The docker command is not on PATH.",
                     fix="Install Docker Desktop (Windows, macOS) or Docker Engine with the Compose plugin (Linux).")]
    except subprocess.TimeoutExpired:
        return [fail(name, "`docker info` did not answer within 20 s: the daemon is hung or still starting.",
                     fix=_docker_start_hint(""))]
    except OSError as e:
        return [fail(name, f"The docker command could not be run: {e}", fix=_docker_start_hint(str(e)))]
    if proc.returncode != 0:
        error = _first_line(proc.stderr) or _first_line(proc.stdout) or f"exit {proc.returncode}"
        return [fail(name, f"Docker daemon is not reachable: {error}", fix=_docker_start_hint(error))]
    ctx.docker_ok = True
    podman = _is_podman()
    out = [ok(name, f"daemon {proc.stdout.strip() or '?'} reachable" + (" (Podman)" if podman else ""))]

    try:
        limits = _docker(["info", "--format", "{{.MemoryLimit}} {{.PidsLimit}}"], timeout=20)
        values = limits.stdout.split() if limits.returncode == 0 else []
    except (OSError, subprocess.TimeoutExpired):
        values = []
    if len(values) == 2 and "false" in values:
        out.append(warn("docker limits", f"The daemon does not enforce memory and/or PID limits "
                                         f"(MemoryLimit={values[0]}, PidsLimit={values[1]}), so the sandbox's "
                                         f"--memory and --pids-limit are silently ignored.",
                        fix="Rootless Docker needs cgroup v2 delegation for these; see Docker's rootless-mode docs."))
    if podman and (ctx.env.get("LLM_PROXY_RESOLVER") or "").strip() != "local":
        out.append(warn("docker", "The docker CLI is talking to Podman. llm-proxy's default resolver is "
                                  "Docker's embedded DNS (127.0.0.11), which Podman does not provide, so it "
                                  "cannot resolve the provider (every call is a 502). Podman is untested.",
                        fix="Set LLM_PROXY_RESOLVER=local in .env, then docker compose up -d --force-recreate llm-proxy"))
    return out


_VERSION = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


def check_compose(ctx: Context) -> List[Check]:
    name = "compose"
    try:
        proc = _docker(["compose", "version", "--short"], timeout=30)
    except FileNotFoundError:
        return [skip(name, "needs the docker command")]
    except (OSError, subprocess.TimeoutExpired) as e:
        return [fail(name, f"`docker compose version` failed: {type(e).__name__}: {e}")]
    if proc.returncode != 0:
        error = _first_line(proc.stderr) or _first_line(proc.stdout) or f"exit {proc.returncode}"
        return [fail(name, f"`docker compose` is not available: {error}",
                     fix="Install the Docker Compose v2 plugin, 2.24 or later. The old standalone "
                         "docker-compose (v1) cannot read this project's compose file.")]
    match = _VERSION.search(proc.stdout)
    if not match:
        return [warn(name, f"Could not read the Compose version from {proc.stdout.strip()[:80]!r}; "
                           f"2.24 or later is needed.")]
    version = (int(match.group(1)), int(match.group(2)))
    found = match.group(0)
    if version < MIN_COMPOSE:
        return [fail(name, f"Docker Compose {found} is older than 2.24. docker-compose.yml uses "
                           f"`env_file: {{path, required: false}}` and the gate uses `up --wait`, which "
                           f"older versions reject.",
                     fix="Update Docker Desktop, or the docker-compose-plugin package, to Compose 2.24 or later.")]
    return [ok(name, f"Docker Compose {found}")]


# ── Ports ─────────────────────────────────────────────────────────────────────

def _port_busy(port: int) -> bool:
    """Whether something already holds 127.0.0.1:<port>."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        pass
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if os.name != "nt":
            # As uvicorn and Docker do, so a closed socket in TIME_WAIT does not
            # read as busy. Not on Windows, where it would let us bind a port in use.
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", port))
        return False
    except OSError:
        return True
    finally:
        sock.close()


def _container_on_port(port: int) -> Optional[str]:
    try:
        proc = _docker(["ps", "--filter", f"publish={port}", "--format", "{{.Names}}"], timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    names = proc.stdout.split() if proc.returncode == 0 else []
    return names[0] if names else None


def _is_creuset_ui(port: int) -> bool:
    # No proxy: this is a loopback request, and HTTP(S)_PROXY must not see it.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(f"http://127.0.0.1:{port}/", timeout=2) as resp:
            return "creuset" in resp.read(8192).decode("utf-8", "replace").lower()
    except Exception:  # pylint: disable=broad-except — anything else on the port is "not ours"
        return False


def check_ports(ctx: Context) -> List[Check]:
    out: List[Check] = []
    raw = (ctx.env.get("ROUTER_HOST_PORT") or "").strip()
    if raw and not (raw.isdigit() and 0 < int(raw) < 65536):
        out.append(fail("ports", f"ROUTER_HOST_PORT={raw!r} is not a port number.",
                        fix=f"Set a number such as {DEFAULT_ROUTER_PORT}, or leave it unset."))
        router_port = None
    else:
        router_port = int(raw) if raw else DEFAULT_ROUTER_PORT

    if router_port is not None:
        name = f"port {router_port}"
        if not _port_busy(router_port):
            out.append(ok(name, "free for the blue/green router"))
        else:
            owner = _container_on_port(router_port) if ctx.docker_ok else None
            if owner == ROUTER_CONTAINER:
                out.append(ok(name, f"in use by Creuset's router ({owner}): the stack is up"))
            else:
                held = f"container {owner}" if owner else "another program"
                out.append(warn(name, f"in use by {held}, so the router cannot publish there. Gate runs do "
                                      f"not need it; `docker compose up -d` (the live slots) does.",
                                fix="Stop what holds it, or set ROUTER_HOST_PORT=<free port> in .env."))

    name = f"port {UI_PORT}"
    if not _port_busy(UI_PORT):
        out.append(ok(name, "free for the results browser"))
    elif _is_creuset_ui(UI_PORT):
        out.append(ok(name, "Creuset's results browser is already running there"))
    else:
        out.append(warn(name, "in use by another program, so the results browser cannot start there.",
                        fix="Stop what holds it, or start the browser on another port: "
                            "python -m uvicorn ui.app:app --host 127.0.0.1 --port <free port>"))
    return out


# ── Infrastructure (sandbox/run_test.py's own checks) ─────────────────────────

# "2026/10/14 07:58:39 [error] 46#46: *21 " in front, ", client: ..., host: ..." behind.
_NGINX_PREFIX = re.compile(r"^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d \[(\w+)\] \d+#\d+: (\*\d+ )?")


def _nginx_reason(line: str) -> str:
    match = _NGINX_PREFIX.match(line)
    if not match:
        return line
    return f"[{match.group(1)}] " + line[match.end():].split(", client:")[0]


def _proxy_log_lines(markers: Tuple[str, ...], tail: int = 100) -> List[str]:
    """Recent llm-proxy log lines containing any of `markers`, newest last, without nginx's preamble."""
    try:
        proc = _docker(["logs", "--tail", str(tail), _proxy_container()], timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return []
    # nginx and the entrypoint write their errors to stderr, so it goes last.
    lines = f"{proc.stdout}\n{proc.stderr}".splitlines()
    return [_nginx_reason(ln.strip())[:400] for ln in lines if any(m in ln for m in markers)]


def check_infra(ctx: Context) -> List[Check]:
    if not ctx.docker_ok:
        return [skip("infra", "needs Docker"), skip("agent image", "needs Docker")]
    out: List[Check] = []
    image_problem: Optional[str] = None
    try:
        ref, ctx.image_id = run_test.resolve_image(ctx.image)
        out.append(ok("agent image", f"{ref} ({ctx.image_id[7:19]})"))
    except RuntimeError as e:
        image_problem = str(e)
        out.append(fail("agent image", image_problem))

    problems = run_test.preflight(ctx.image) if ctx.image else run_test.preflight()
    # Reported on their own lines above: the image, and AGENT_MODEL (check_agent_settings).
    problems = [p for p in problems if p != image_problem and not p.startswith("AGENT_MODEL")]
    proxy = _proxy_container()
    for problem in problems:
        fix = None
        if f"'{proxy}'" in problem:
            # The proxy refuses to start on a setting it does not accept, and says
            # which. Its validation lines never contain the key.
            refused = _proxy_log_lines(("05-creuset-validate.envsh: ERROR", "[emerg]"))
            if refused:
                fix = (f"llm-proxy refused to start: {refused[-1]} Fix that setting in .env, then "
                       f"docker compose up -d llm-proxy")
        out.append(fail("infra", problem, fix=fix))
    if not problems:
        ctx.infra_ok = True
        out.append(ok("infra", f"network {_network()} is internal; {proxy} and {_mock_container()} are healthy"))
    return out


def check_proxy_settings(ctx: Context) -> List[Check]:
    """llm-proxy reads the key when it is created: an edited .env has not reached a running one."""
    name = "llm-proxy settings"
    if not ctx.infra_ok:
        return []
    try:
        proc = _docker(["inspect", "--format", "{{json .Config.Env}}", _proxy_container()], timeout=20)
        pairs = json.loads(proc.stdout) if proc.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        pairs = None
    if not isinstance(pairs, list):
        return [warn(name, "Could not read llm-proxy's settings to compare them with this environment.")]
    running = dict(str(p).split("=", 1) for p in pairs if "=" in str(p))
    wanted = {"LLM_API_KEY": (ctx.env.get("LLM_API_KEY") or "").strip(),
              "LLM_UPSTREAM_HOST": _upstream_host(ctx.env)}
    # Values are compared here and never printed.
    stale = [var for var, value in wanted.items() if var in running and running[var].strip() != value]
    if stale:
        return [fail(name, f"llm-proxy is running with a different {' and '.join(stale)} than this environment "
                           f"(values not shown). It reads them only when it is created, so every agent call "
                           f"would use the old one.",
                     fix="docker compose up -d --force-recreate llm-proxy")]
    return [ok(name, "running with this environment's LLM_API_KEY and LLM_UPSTREAM_HOST")]


_HEALTH = ("import sys, urllib.request; "
           "sys.stdout.write(urllib.request.urlopen(sys.argv[1], timeout=10).read().decode())")


def check_mock_services(ctx: Context) -> List[Check]:
    name = "mock-services"
    if not ctx.infra_ok:
        return []
    try:
        proc = _docker(["exec", _mock_container(), "python", "-c", _HEALTH, "http://localhost:8001/health"])
        health = json.loads(proc.stdout) if proc.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        health = None
    if not isinstance(health, dict):
        return [warn(name, "Could not read mock-services' /health from inside its container.")]
    if "strict_runs" not in health:
        return [warn(name, "mock-services runs an image from before per-run worlds became create-once: an "
                           "agent could still reset its own audit log there.",
                     fix="docker compose build mock-services && docker compose up -d --force-recreate mock-services")]
    mode = "strict (agent calls must name their run)" if health["strict_runs"] else "lenient (the default)"
    return [ok(name, f"current image; runs are {mode}")]


def check_isolation(ctx: Context) -> List[Check]:
    name = "isolation"
    if not ctx.infra_ok:
        return [skip(name, "needs llm-proxy, mock-services and the sandbox network (see infra)")]
    probe = run_test.isolation_probe()
    if probe.get("ok"):
        return [ok(name, "gateway reachable, other paths 403, no internet TCP, no DNS "
                         "(probed from a container on the sandbox network)")]
    if probe.get("error"):
        return [fail(name, f"The isolation probe could not run: {probe['error']}")]
    reasons = []
    if probe.get("llm_proxy_health") != 200:
        reasons.append(f"llm-proxy is not reachable from the sandbox ({probe.get('llm_proxy_health')})")
    if probe.get("llm_proxy_other_path") != 403:
        reasons.append(f"llm-proxy did not refuse a non-API path ({probe.get('llm_proxy_other_path')}), "
                       f"so it is not running Creuset's config")
    if probe.get("mock_services_health") != 200:
        reasons.append(f"mock-services is not reachable from the sandbox ({probe.get('mock_services_health')})")
    if probe.get("internet_tcp_1_1_1_1") == "connected":
        reasons.append("a sandbox container reached the internet over TCP")
    if probe.get("internet_dns_example_com") == "resolved":
        reasons.append("a sandbox container resolved a public DNS name")
    return [fail(name, "; ".join(reasons) or f"unexpected probe result {probe}",
                 fix="Recreate the stack from docker-compose.yml (docker compose down, then docker compose up -d "
                     "llm-proxy mock-services). The sandbox network must be internal: true.")]


# ── Live traffic ──────────────────────────────────────────────────────────────

def _mock_image_id(ctx: Context) -> Optional[str]:
    """The image the doctor's helper containers run: mock-services', which always has Python."""
    if ctx.mock_image is None:
        ctx.mock_image = ""
        for args in (["inspect", "--format", "{{.Image}}", _mock_container()],
                     ["image", "inspect", "--format", "{{.Id}}", MOCK_IMAGE_TAG]):
            try:
                proc = _docker(args)
            except (OSError, subprocess.TimeoutExpired):
                continue
            found = proc.stdout.strip()
            if proc.returncode == 0 and found.startswith("sha256:"):
                ctx.mock_image = found
                break
    return ctx.mock_image or None


_WRITE_PROBE = (
    "import os, uuid\n"
    "path = '/creuset-live/.creuset-doctor-%s.tmp' % uuid.uuid4().hex\n"
    "try:\n"
    "    with open(path, 'w') as f:\n"
    "        f.write('creuset doctor write probe')\n"
    "    os.remove(path)\n"
    "except OSError as e:\n"
    "    print('denied: %s' % (e.strerror or e))\n"
    "else:\n"
    "    print('writable')\n"
)


def _probe_write(directory: Path, uid: str, gid: str, image: str) -> Optional[str]:
    """
    'writable' or 'denied: <why>', found by writing as uid:gid from a container
    shaped like a slot (no capabilities, so no root override); None if the probe
    itself could not run.
    """
    name = _helper_name()
    cmd = ["run", "--rm", "--name", name, "--network", "none", "--read-only", "--cap-drop", "ALL",
           "--security-opt", "no-new-privileges", "--no-healthcheck", *_helper_labels(name),
           "--user", f"{uid}:{gid}", "-v", f"{directory.resolve().as_posix()}:/creuset-live",
           "--entrypoint", "python", image, "-c", _WRITE_PROBE]
    try:
        proc = _docker(cmd, timeout=60)
    except subprocess.TimeoutExpired:
        _remove_quietly(name)
        return None
    except OSError:
        return None
    verdict = _last_line(proc.stdout)
    return verdict if proc.returncode == 0 and verdict.startswith(("writable", "denied")) else None


def _writable_by(path: Path, uid: int, gid: int) -> bool:
    """POSIX permission bits as a process with exactly uid:gid and no capabilities sees them."""
    st = path.stat()
    if st.st_uid == uid:
        bits = (st.st_mode >> 6) & 0o7
    elif st.st_gid == gid:
        bits = (st.st_mode >> 3) & 0o7
    else:
        bits = st.st_mode & 0o7
    return bits & 0o3 == 0o3  # write and search


def check_live_traffic(ctx: Context) -> List[Check]:
    name = "live traffic"
    uid = (ctx.env.get("CREUSET_UID") or "").strip() or DEFAULT_SLOT_ID
    gid = (ctx.env.get("CREUSET_GID") or "").strip() or DEFAULT_SLOT_ID
    if not (uid.isdigit() and gid.isdigit()):
        return [fail(name, f"CREUSET_UID={uid!r} / CREUSET_GID={gid!r}: both must be numeric ids.",
                     fix="On Linux: CREUSET_UID=$(id -u) and CREUSET_GID=$(id -g), or leave them unset.")]
    directory = ctx.root / "logs" / "live_traffic"
    rel = _rel(directory, ctx.root)
    why = (f"The live slots run as {uid}:{gid} and write every request's transcript there; when they "
           f"cannot, the monitor watches an empty directory and never rolls back. Gate runs are not affected.")
    fix = (f"On Linux, set CREUSET_UID=$(id -u) and CREUSET_GID=$(id -g) in .env so the slots run as you, "
           f"or: sudo chown {uid}:{gid} {rel}")
    if not directory.is_dir():
        return [warn(name, f"{rel} does not exist. Docker would create it owned by root when the slots start, "
                           f"and they could not write to it. {why}", fix=f"mkdir {rel}")]

    transport = (ctx.env.get("CREUSET_SCENARIO_TRANSPORT") or "bind").strip().lower()
    if ctx.docker_ok and transport != "volume":
        image = _mock_image_id(ctx)
        verdict = _probe_write(directory, uid, gid, image) if image else None
        if verdict == "writable":
            return [ok(name, f"{rel} is writable by the slots' {uid}:{gid} (checked from a container)")]
        if verdict:
            return [warn(name, f"{rel} is not writable by {uid}:{gid} from a container ({verdict}). {why}",
                         fix=fix + ". With rootless Docker, uids are remapped: chmod o+w the directory instead.")]

    if not sys.platform.startswith("linux") or not hasattr(os, "getuid"):
        return [skip(name, "not checked: needs Docker here (Docker Desktop maps file ownership, so the host's "
                           "permissions say nothing about what a slot can write)")]
    if _writable_by(directory, int(uid), int(gid)):
        return [ok(name, f"{rel} is writable by {uid}:{gid} (host permissions; not checked from a container)")]
    st = directory.stat()
    return [warn(name, f"{rel} (owner {st.st_uid}:{st.st_gid}, mode {oct(st.st_mode & 0o777)[2:]}) is not "
                       f"writable by {uid}:{gid}. {why}", fix=fix)]


# ── Variants ──────────────────────────────────────────────────────────────────

def _is_bundled(ctx: Context, ref: str) -> bool:
    if ref == _bundled_ref(ctx.env):
        return True
    if not ctx.docker_ok:
        return False
    try:
        _, image_id = run_test.resolve_image(ref)
    except RuntimeError:
        return False
    check = getattr(run_test, "is_bundled_image", None)
    return bool(callable(check) and check(image_id))


def _canary_problem(ctx: Context, variant: str) -> Optional[str]:
    fn = getattr(run_test, "canary_warning", None)
    if callable(fn):
        return fn(variant, image=ctx.image) if ctx.image else fn(variant)
    # Fallback for a harness without it: the same rule, bundled prompts only.
    try:
        judge_dir = str(_ROOT / "judge")
        if judge_dir not in sys.path:
            sys.path.append(judge_dir)
        markers = importlib.import_module("rule_checks").canary_markers()
        text = (ctx.root / "agent" / "variants" / f"{variant}.txt").read_text(encoding="utf-8")
    except Exception:  # pylint: disable=broad-except — a warning must never stop the doctor
        return None
    if markers and not any(m in text for m in markers):
        return (f"agent/variants/{variant}.txt contains no canary marker ({', '.join(markers)}), so the "
                f"canary check cannot detect a leak of this prompt.")
    return None


def check_variants(ctx: Context) -> List[Check]:
    ref = (ctx.image or _default_image(ctx.env)).strip()
    bundled = _is_bundled(ctx, ref)
    out: List[Check] = []
    if (ctx.env.get("CREUSET_CANARY") is not None) and not (ctx.env.get("CREUSET_CANARY") or "").strip():
        out.append(warn("canary", "CREUSET_CANARY is set but empty: the canary leak check is skipped in every "
                                  "report (SKIP, never PASS).",
                        fix="Unset it to use the bundled prompts' marker, or set it to the marker your prompt carries."))
    variants = list(ctx.variants)
    if not variants and bundled:
        variants = sorted(p.stem for p in (ctx.root / "agent" / "variants").glob("*.txt"))
    if not variants:
        out.append(skip("variants", f"{ref} is not the bundled agent image, so its variants are opaque to "
                                    f"Creuset; name them with --variant. Its prompt cannot be read for a "
                                    f"canary: set CREUSET_CANARY to the marker it carries."))
        return out
    compared = bundled and ctx.docker_ok and ctx.image_id is not None
    for variant in variants:
        name = f"variant {variant}"
        problem = run_test.validate_variant(variant, image=ctx.image) if ctx.image else run_test.validate_variant(variant)
        if problem:
            out.append(fail(name, problem))
            continue
        canary = _canary_problem(ctx, variant)
        if not bundled:
            detail = "name accepted; passed to the image as-is"
        elif compared:
            detail = "prompt matches the copy inside the image"
        else:
            detail = "prompt found; not compared with the image (needs Docker and the image)"
        if bundled and not canary:
            detail += "; carries the canary"
        out.append(ok(name, detail))
        if canary:
            out.append(warn(name, canary))
    return out


# ── LLM probes (--llm) ────────────────────────────────────────────────────────

# Runs inside a throwaway container on the sandbox network, in the mock-services
# image, and calls the agent's route the way an agent does: through llm-proxy,
# with the placeholder key agents hold (the proxy injects the real one).
_LLM_PROBE = r"""
import json, sys, urllib.request, urllib.error
url, model, timeout = sys.argv[1], sys.argv[2], float(sys.argv[3])
body = json.dumps({"model": model, "max_tokens": 1,
                   "messages": [{"role": "user", "content": "Reply with OK."}]}).encode()
req = urllib.request.Request(url, data=body, method="POST", headers={
    "Content-Type": "application/json", "Authorization": "Bearer sandbox-placeholder-key"})
def keep(headers):
    return {k.lower(): v for k, v in (headers or {}).items()
            if k.lower().startswith("x-ratelimit") or k.lower() == "retry-after"}
try:
    with urllib.request.urlopen(req, timeout=timeout) as r:
        out = {"status": r.status, "headers": keep(r.headers), "body": r.read(4000).decode("utf-8", "replace")}
except urllib.error.HTTPError as e:
    out = {"status": e.code, "headers": keep(e.headers), "body": e.read(4000).decode("utf-8", "replace")}
except Exception as e:
    out = {"status": None, "error": "%s: %s" % (type(e).__name__, e)}
print(json.dumps(out))
"""


def _agent_llm_request(url: str, model: str, image: str) -> Dict[str, Any]:
    """One max_tokens=1 call along the agent's route. Always returns a response dict."""
    name = _helper_name()
    cmd = ["run", "--rm", "--name", name, "--network", _network(), "--read-only", "--cap-drop", "ALL",
           "--security-opt", "no-new-privileges", "--pids-limit", "64", "--memory", "128m", "--no-healthcheck",
           *_helper_labels(name), "--entrypoint", "python", image, "-c", _LLM_PROBE, url, model, str(_LLM_TIMEOUT)]
    try:
        proc = _docker(cmd, timeout=_LLM_TIMEOUT + 30)
    except subprocess.TimeoutExpired:
        _remove_quietly(name)
        return {"status": None, "timeout": True, "error": f"no answer within {_LLM_TIMEOUT + 30} s"}
    except OSError as e:
        return {"status": None, "probe_failed": True, "error": f"{type(e).__name__}: {e}"}
    try:
        data = json.loads(_last_line(proc.stdout, limit=None))  # a clipped line is not JSON
    except json.JSONDecodeError:
        data = None
    if not isinstance(data, dict):
        return {"status": None, "probe_failed": True,
                "error": _last_line(proc.stderr) or f"probe container exited {proc.returncode}"}
    return data


def _root_cause(exc: BaseException) -> str:
    """The innermost exception: the SDK's own wrapper says only "Connection error."."""
    seen = set()
    current = exc
    while (current.__cause__ or current.__context__) is not None and id(current) not in seen:
        seen.add(id(current))
        current = current.__cause__ or current.__context__
    return f"{type(current).__name__}: {current}"


def _judge_llm_request() -> Dict[str, Any]:
    """
    One max_tokens=1 call to JUDGE_API_BASE through the same SDK, key choice and
    TLS stack as the judge, but with no retries: a 429 is the answer, not a
    reason to wait.
    """
    from openai import APIConnectionError, APIStatusError, APITimeoutError, OpenAI

    judge = _model_judge()
    base, key = judge._resolve_endpoint()  # the judge's own rule for which key may go where
    client = OpenAI(base_url=base, api_key=key, max_retries=0, timeout=_LLM_TIMEOUT)

    def keep(headers: Any) -> Dict[str, str]:
        return {k.lower(): v for k, v in dict(headers or {}).items()
                if k.lower().startswith("x-ratelimit") or k.lower() == "retry-after"}

    try:
        raw = client.chat.completions.with_raw_response.create(
            model=judge.JUDGE_MODEL, max_tokens=1, messages=[{"role": "user", "content": "Reply with OK."}])
        return {"status": raw.status_code, "headers": keep(raw.headers), "body": ""}
    except APIStatusError as e:
        return {"status": e.status_code, "headers": keep(e.response.headers), "body": e.response.text[:4000]}
    except APITimeoutError:
        return {"status": None, "timeout": True, "error": f"no answer within {_LLM_TIMEOUT} s"}
    except APIConnectionError as e:
        return {"status": None, "error": _root_cause(e)}


def _provider_message(body: str) -> str:
    """The provider's own error message, one line, clipped."""
    text = body or ""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        data = None
    if isinstance(data, dict):
        err = data.get("error", data)
        if isinstance(err, dict):
            text = str(err.get("message") or err.get("code") or err)
        elif err:
            text = str(err)
        elif data.get("message"):
            text = str(data["message"])
    return " ".join(text.split())[:240]


def _ratelimit_summary(headers: Mapping[str, str]) -> str:
    keys = sorted(k for k in headers if k.startswith("x-ratelimit") or k == "retry-after")
    return ", ".join(f"{k}={headers[k]}" for k in keys)


@dataclass
class _Route:
    """Which route a probe took, for the advice."""

    name: str
    who: str  # "agent" | "judge"
    host: str
    model_var: str
    model: str
    key_hint: str
    base: str


_SSL_MARKERS = ("certificate verify", "certificate_verify_failed", "ssl_do_handshake", "self-signed",
                "self signed", "unable to get local issuer")


def classify(resp: Mapping[str, Any], route: _Route, proxy_errors: Callable[[], List[str]] = lambda: []) -> Check:
    """Turn one probe response into a check with advice. Never includes the key."""
    status = resp.get("status")
    headers = {str(k).lower(): str(v) for k, v in (resp.get("headers") or {}).items()}
    body = str(resp.get("body") or "")
    message = _provider_message(body)
    said = f": {message}" if message else ""
    agent = route.who == "agent"
    via = "through llm-proxy " if agent else ""
    recreate = (" llm-proxy reads the key only when it is created: after editing .env, run "
                "docker compose up -d --force-recreate llm-proxy") if agent else ""

    if status is None:
        error = str(resp.get("error") or "no response")
        if resp.get("timeout"):
            return fail(route.name, f"{route.host} did not answer {via}({error}).",
                        fix="The provider may be down or very slow; try again later.", kind=PROVIDER)
        if agent:
            return fail(route.name, f"The probe could not reach llm-proxy at {route.base}: {error}",
                        fix="docker compose up -d llm-proxy mock-services; then check AGENT_API_BASE.")
        if any(m in error.lower() for m in _SSL_MARKERS):
            return fail(route.name, f"This machine could not verify the TLS certificate of {route.host}: {error}",
                        fix="Check JUDGE_API_BASE's host. Behind a TLS-inspecting proxy, point SSL_CERT_FILE at "
                            "a PEM bundle that includes its CA.")
        return fail(route.name, f"{route.host} is unreachable from this machine: {error}",
                    fix="Check JUDGE_API_BASE, your connection and any HTTPS_PROXY setting.", kind=PROVIDER)

    if 200 <= status < 300:
        limits = _ratelimit_summary(headers)
        return ok(route.name, f"{route.model} answered {via}from {route.host}" + (f" ({limits})" if limits else ""))

    if status in (400, 422):
        if re.search(r"max_(completion_)?tokens", body):
            return warn(route.name, f"{route.host} accepted the key but refused the probe's max_tokens=1 "
                                    f"({status}{said}).",
                        fix="Usually harmless: the probe's request is not the agent's or the judge's.")
        return fail(route.name, f"{route.host} refused the request ({status}{said}).",
                    fix=f"If it names the model, set {route.model_var} to one {route.host} serves.")

    if status == 401:
        fix = f"Check {route.key_hint} is a valid key for {route.host}."
        if agent:
            fix += f"{recreate}. A provider that takes the key in another header needs LLM_AUTH_HEADER (e.g. api-key)."
        return fail(route.name, f"{route.host} rejected the key ({status}{said}).", fix=fix)

    if status == 403:
        if agent and "creuset llm-proxy: egress denied" in body:
            path = urlsplit(route.base).path.rstrip("/") + "/chat/completions"
            return fail(route.name, f"llm-proxy refused the path {path}: it forwards only /v1/<endpoint> and "
                                    f"/openai/v1/<endpoint>, for the endpoints in LLM_ALLOWED_ENDPOINTS.",
                        fix=f"Set AGENT_API_BASE to http://llm-proxy:{PROXY_PORT}/openai/v1 (Groq) or .../v1, and "
                            f"keep chat/completions in LLM_ALLOWED_ENDPOINTS.")
        return fail(route.name, f"{route.host} refused the request ({status}{said}).",
                    fix=f"The key may lack access to {route.model_var}={route.model}, or the provider blocks this "
                        f"network or region. Check the account's permissions.")

    if status == 404:
        if "model" in body.lower():
            return fail(route.name, f"{route.host} does not serve {route.model_var}={route.model} ({status}{said}).",
                        fix=f"Set {route.model_var} to a model id {route.host} lists at {route.base}/models.")
        hint = ("Groq serves /openai/v1, OpenAI and most others /v1: set AGENT_API_BASE accordingly. A provider "
                "under a sub-path takes LLM_UPSTREAM_PATH_PREFIX (e.g. /api for OpenRouter).") if agent else \
            "Check JUDGE_API_BASE's path: /openai/v1 for Groq, /v1 for OpenAI and most others."
        return fail(route.name, f"{route.host} has no such API path ({status}{said}).", fix=hint)

    if status == 429:
        limits = _ratelimit_summary(headers)
        return fail(route.name, f"{route.host}: rate limit or quota exhausted ({status}{said})"
                                + (f" [{limits}]" if limits else "") + ".",
                    fix=f"Wait for the limit to reset (a daily token quota frees up slowly), or use another "
                        f"{route.model_var} or key. The agent and judge models have separate quotas.",
                    kind=PROVIDER)

    if agent and status in (502, 504):
        lines = proxy_errors()
        last = lines[-1] if lines else ""
        low = last.lower()
        if any(m in low for m in _SSL_MARKERS) or "ssl" in low:
            return fail(route.name, f"llm-proxy could not verify the TLS certificate of {route.host} ({status}): {last}",
                        fix="Check LLM_UPSTREAM_HOST is the provider's API host. Behind a TLS-inspecting "
                            "corporate proxy, mount its CA (PEM) into llm-proxy and set LLM_PROXY_EXTRA_CA_FILE "
                            "to the path inside the container.")
        if "could not be resolved" in low or "no resolver" in low:
            return fail(route.name, f"llm-proxy could not resolve {route.host} ({status}): {last}",
                        fix="Check LLM_UPSTREAM_HOST. On Podman, set LLM_PROXY_RESOLVER=local.")
        return fail(route.name, f"llm-proxy could not get an answer from {route.host} ({status})"
                                + (f": {last}" if last else "") + ".",
                    fix="The provider may be down, or this network blocks it. Try again later.",
                    kind=PROVIDER)

    return fail(route.name, f"{route.host} answered {status}{said}.",
                fix="A provider-side failure; try again later.", kind=PROVIDER)


def _proxy_errors() -> List[str]:
    return _proxy_log_lines(("[error]", "[crit]", "[alert]", "[emerg]"), tail=50)


def check_agent_llm(ctx: Context) -> List[Check]:
    name = "LLM: agent"
    if not ctx.llm:
        return [skip(name, "not called: add --llm for one max_tokens=1 call through llm-proxy "
                           "(and one to the judge), a few tokens of quota")]
    model = (ctx.env.get("AGENT_MODEL") or "").strip()
    if not model:
        return [skip(name, "needs AGENT_MODEL")]
    if not ctx.infra_ok:
        return [skip(name, "needs llm-proxy, mock-services and the sandbox network (see infra)")]
    image = _mock_image_id(ctx)
    if not image:
        return [fail(name, f"Could not find the {_mock_container()} image to run the probe in.",
                     fix="docker compose build mock-services")]
    base = _agent_base(ctx.env)
    url = base.rstrip("/") + "/chat/completions"
    route = _Route(name, "agent", _upstream_host(ctx.env), "AGENT_MODEL", model,
                   "LLM_API_KEY (llm-proxy injects it)", base)
    return [classify(_agent_llm_request(url, model, image), route, _proxy_errors)]


def check_judge_llm(ctx: Context) -> List[Check]:
    name = "LLM: judge"
    if not ctx.llm or not ctx.judge:
        return []
    if not ctx.judge_call:
        return [skip(name, "--no-judge-call")]
    if not ctx.judge_ok:
        return [skip(name, "fix the judge settings first (see judge)")]
    base = (ctx.env.get("JUDGE_API_BASE") or "").strip()
    judge = _model_judge()
    if not callable(getattr(judge, "_resolve_endpoint", None)):
        return [skip(name, "not called: judge/model_judge.py no longer exposes its endpoint resolution")]
    key_hint = "JUDGE_API_KEY" if (ctx.env.get("JUDGE_API_KEY") or "").strip() else \
        "JUDGE_API_KEY (or LLM_API_KEY, which the judge falls back to)"
    route = _Route(name, "judge", urlsplit(base).hostname or base, "JUDGE_MODEL",
                   str(getattr(judge, "JUDGE_MODEL", "?")), key_hint, base.rstrip("/"))
    return [classify(_judge_llm_request(), route)]


# ── Running it ────────────────────────────────────────────────────────────────

STEPS: List[Callable[[Context], List[Check]]] = [
    check_python, check_env_file, check_llm_key, check_agent_settings, check_agent_route, check_judge_config,
    check_docker, check_compose, check_ports, check_infra, check_proxy_settings, check_mock_services,
    check_isolation, check_live_traffic, check_variants, check_agent_llm, check_judge_llm,
]


def run_checks(ctx: Context) -> List[Check]:
    """Every check, in order, each one redacted. A check that crashes is a FAIL, never a traceback."""
    redact = make_redactor(ctx.env)
    checks: List[Check] = []
    for step in STEPS:
        try:
            found = step(ctx)
        except Exception as e:  # pylint: disable=broad-except — fail closed, and keep checking
            label = step.__name__.removeprefix("check_").replace("_", " ")
            found = [fail(label, f"The doctor could not finish this check: {type(e).__name__}: {e}",
                          fix="Please report this as a bug, with the line above.")]
        checks.extend(found)
    return [Check(c.name, c.status, redact(c.detail), redact(c.fix) if c.fix else None, c.kind) for c in checks]


_STYLE = {OK: ("✓", "green"), WARN: ("!", "yellow"), FAIL: ("✗", "red"), SKIP: ("-", "dim")}


def render(checks: List[Check], code: int, console: Console) -> None:
    table = Table.grid(padding=(0, 1))
    table.add_column(no_wrap=True)
    table.add_column(no_wrap=True, style="bold")
    table.add_column()
    for c in checks:
        icon, color = _STYLE[c.status]
        detail = Text(c.detail, style="dim" if c.status == SKIP else "")
        if c.fix and c.status in (FAIL, WARN):
            detail.append("\n→ " + c.fix, style="cyan")
        table.add_row(Text(icon, style=color), Text(c.name), detail)
    console.print(Text("Creuset doctor", style="bold"))
    console.print(table)
    problems = sum(c.status == FAIL for c in checks)
    warnings = sum(c.status == WARN for c in checks)
    if code == EXIT_OK:
        summary = Text("Ready." + (f" {warnings} warning(s) above." if warnings else ""), style="green")
    elif code == EXIT_CONFIG:
        summary = Text(f"{problems} problem(s), {warnings} warning(s): fix the configuration before running "
                       f"anything (exit 2).", style="red")
    else:
        summary = Text("The configuration looks right, but the provider is unreachable or out of quota (exit 3).",
                       style="red")
    console.print(summary)


def to_json(checks: List[Check], code: int) -> Dict[str, Any]:
    return {
        "schema_version": 1,
        "exit_code": code,
        "ready": code == EXIT_OK,
        "summary": {s: sum(c.status == s for c in checks) for s in (OK, WARN, FAIL, SKIP)},
        "checks": [asdict(c) for c in checks],
    }


def build_context(*, image: Optional[str], variants: List[str], llm: bool, judge: bool,
                  judge_call: bool, root: Optional[Path] = None) -> Context:
    root = root or _ROOT
    env_file = root / ".env"
    try:
        values = dotenv_values(env_file) if env_file.is_file() else {}
    except (OSError, UnicodeDecodeError):
        values = {}
    return Context(env=os.environ, dotenv=dict(values), root=root, image=image, variants=variants,
                   llm=llm, judge=judge, judge_call=judge_call)


app = typer.Typer(add_completion=False)


@app.command()
def main(
    llm: bool = typer.Option(False, "--llm", help="Also make one max_tokens=1 call along the agent's route "
                                                  "(through llm-proxy, from a container on the sandbox network) and "
                                                  "one to JUDGE_API_BASE. Spends a few tokens of quota."),
    no_judge_call: bool = typer.Option(False, "--no-judge-call", help="With --llm, skip the call to JUDGE_API_BASE."),
    skip_model_judge: bool = typer.Option(False, "--skip-model-judge",
                                          help="Rule-only use: do not check the judge's settings or call it."),
    image: Optional[str] = typer.Option(None, "--image", help="Agent image to check (default: AGENT_IMAGE, else "
                                                              "AGENT_IMAGE_TAG, else creuset-agent:latest)."),
    variant: Optional[List[str]] = typer.Option(None, "--variant", help="Variant to check; repeatable. Default: "
                                                                        "every prompt in agent/variants/ for the "
                                                                        "bundled image."),
    strict: bool = typer.Option(False, "--strict", help="Treat warnings as configuration problems (exit 2)."),
    json_out: bool = typer.Option(False, "--json", help="Print the result as JSON on stdout; the human report "
                                                        "goes to stderr."),
) -> None:
    """Check that everything a Creuset run needs is in place, before a run spends quota finding out.

    Exit 0 ready, 2 configuration problem, 3 provider unreachable or quota exhausted."""
    ctx = build_context(image=image, variants=list(variant or []), llm=llm, judge=not skip_model_judge,
                        judge_call=not no_judge_call)
    checks = run_checks(ctx)
    code = exit_code(checks, strict=strict)
    render(checks, code, Console(stderr=json_out, highlight=False))
    if json_out:
        print(json.dumps(to_json(checks, code), indent=2))
    raise typer.Exit(code=code)


if __name__ == "__main__":
    app()
