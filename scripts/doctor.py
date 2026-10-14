"""
scripts/doctor.py
──────────────────
Is this machine ready to run Creuset? Every check says what it found and, when
something is wrong, the command that fixes it.

    python scripts/doctor.py              # host, config, Docker, stack
    python scripts/doctor.py --probe      # + start a container and prove isolation
    python scripts/doctor.py --online     # + one free call to /models: is the key valid?
    python scripts/doctor.py --json       # machine-readable, for CI

Nothing here spends provider quota: --online lists models, which costs no
tokens. Only the standard library is needed to run it (rich, when installed,
makes the table nicer), because "the dependencies are not installed" is one of
the things it has to be able to say.

Exit code: 0 when nothing FAILs (warnings allowed), 1 otherwise.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
OK, WARN, FAIL, SKIP = "ok", "warn", "fail", "skip"

# Host-side imports the CLIs need (requirements.txt), by import name.
HOST_MODULES = ("typer", "rich", "yaml", "jsonschema", "openai", "dotenv", "httpx", "fastapi", "uvicorn")
# Placeholder values from .env.example: present, but not configured.
PLACEHOLDERS = {"your-key-here", "changeme", "sk-...", ""}
# `env_file: {path, required: false}` in docker-compose.yml needs this.
MIN_COMPOSE = (2, 24, 0)


@dataclass
class Check:
    group: str
    name: str
    status: str
    detail: str
    fix: Optional[str] = None


# ── Environment ───────────────────────────────────────────────────────────────

def _parse_env_file(path: Path) -> Dict[str, str]:
    """KEY=VALUE lines, as python-dotenv would read them for these purposes."""
    values: Dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.removeprefix("export ").partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        else:
            value = value.split(" #", 1)[0].strip()
        values[key.strip()] = value
    return values


def load_env(root: Path = ROOT) -> Tuple[Dict[str, str], bool]:
    """The effective configuration: .env, overridden by the real environment."""
    path = root / ".env"
    file_values = _parse_env_file(path) if path.is_file() else {}
    return {**file_values, **os.environ}, path.is_file()


def _run(args: List[str], timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                          encoding="utf-8", errors="replace")


def _docker(args: List[str], timeout: int = 30) -> Optional[subprocess.CompletedProcess]:
    try:
        return _run(["docker", *args], timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None


# ── Host ──────────────────────────────────────────────────────────────────────

def check_python() -> Check:
    v = sys.version_info
    found = f"Python {v.major}.{v.minor}.{v.micro}"
    if v < (3, 11):
        return Check("host", "python", FAIL, f"{found}; Creuset needs 3.11 or newer",
                     "Install Python 3.11+ and recreate the virtualenv")
    return Check("host", "python", OK, found)


def check_modules() -> Check:
    missing = [m for m in HOST_MODULES if importlib.util.find_spec(m) is None]
    if missing:
        return Check("host", "dependencies", FAIL, f"not importable: {', '.join(missing)}",
                     "pip install -r requirements.txt")
    return Check("host", "dependencies", OK, f"{len(HOST_MODULES)} host packages importable")


def check_env_file(present: bool) -> Check:
    if present:
        return Check("config", ".env", OK, "found")
    return Check("config", ".env", WARN, "no .env; only the process environment is used",
                 "cp .env.example .env   (then fill in LLM_API_KEY and the models)")


def check_config(env: Dict[str, str]) -> List[Check]:
    """Required settings, by name only: a value is never printed."""
    out: List[Check] = []
    key = env.get("LLM_API_KEY", "")
    if key.strip() in PLACEHOLDERS:
        out.append(Check("config", "LLM_API_KEY", FAIL, "missing or still the .env.example placeholder",
                         "Set LLM_API_KEY in .env (given only to llm-proxy and the host judge)"))
    else:
        out.append(Check("config", "LLM_API_KEY", OK, f"set ({len(key)} characters)"))
    for name, why in (("AGENT_MODEL", "the model the agent under test requests"),
                      ("LLM_UPSTREAM_HOST", "the one host llm-proxy sends the key to")):
        if not env.get(name, "").strip():
            out.append(Check("config", name, FAIL, f"not set: {why}", f"Set {name} in .env"))
        else:
            out.append(Check("config", name, OK, env[name].strip()))
    out.append(check_judge_config(env))
    return out


def check_judge_config(env: Dict[str, str]) -> Check:
    """The judge's own rules (model_judge._resolve_endpoint): where its key may go."""
    model = env.get("JUDGE_MODEL", "").strip()
    rule_only = "the LLM judge would fail every case closed; rule-only runs (--skip-model-judge) still work"
    if not model:
        return Check("config", "judge", WARN, f"JUDGE_MODEL not set: {rule_only}",
                     "Set JUDGE_API_BASE and JUDGE_MODEL in .env")
    sys.path.insert(0, str(ROOT / "judge"))
    try:
        from model_judge import JudgeConfigError, _resolve_endpoint
    except ImportError as e:
        return Check("config", "judge", SKIP, f"cannot load judge/model_judge.py ({e})")
    try:
        base, _key = _resolve_endpoint(env)
    except JudgeConfigError as e:
        return Check("config", "judge", WARN, f"{e} Until then, {rule_only}.",
                     "Fix JUDGE_API_BASE / JUDGE_API_KEY in .env")
    return Check("config", "judge", OK, f"{model} at {base}")


def check_prefix(env: Dict[str, str]) -> Check:
    prefix = env.get("CREUSET_PREFIX", "")
    if not re.fullmatch(r"(?:[a-z0-9][a-z0-9_-]{0,31})?", prefix):
        return Check("config", "CREUSET_PREFIX", FAIL, f"{prefix!r} is not a valid name prefix",
                     "Use lower-case letters, digits, '-' and '_' (e.g. ci-), or unset it")
    return Check("config", "CREUSET_PREFIX", OK, repr(prefix) if prefix else "(none)")


def check_logs_writable(root: Path = ROOT) -> Check:
    logs = root / "logs"
    try:
        logs.mkdir(exist_ok=True)
        probe = logs / ".doctor-write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except OSError as e:
        return Check("host", "logs/", FAIL, f"not writable: {e}", f"Make {logs} writable")
    return Check("host", "logs/", OK, "writable")


# ── Docker ────────────────────────────────────────────────────────────────────

def check_docker() -> Check:
    if shutil.which("docker") is None:
        return Check("docker", "docker CLI", FAIL, "not on PATH",
                     "Install Docker Desktop (or Docker Engine + the compose plugin)")
    info = _docker(["info", "--format", "{{.ServerVersion}}"], timeout=20)
    if info is None or info.returncode != 0:
        return Check("docker", "daemon", FAIL, "not reachable", "Start Docker Desktop / the Docker daemon")
    return Check("docker", "daemon", OK, f"Docker {info.stdout.strip()}")


def _version_tuple(text: str) -> Optional[Tuple[int, ...]]:
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", text)
    return tuple(int(x) for x in m.groups()) if m else None


def check_compose() -> Check:
    proc = _docker(["compose", "version", "--short"])
    if proc is None or proc.returncode != 0:
        return Check("docker", "compose", FAIL, "the `docker compose` plugin is missing",
                     "Install Docker Compose v2 (docker-compose v1 is not supported)")
    version = _version_tuple(proc.stdout)
    if version is None or version < MIN_COMPOSE:
        need = ".".join(map(str, MIN_COMPOSE))
        return Check("docker", "compose", FAIL, f"{proc.stdout.strip()}; docker-compose.yml needs {need}+",
                     "Update Docker Desktop / the compose plugin")
    return Check("docker", "compose", OK, proc.stdout.strip())


def _names(env: Dict[str, str]) -> Dict[str, str]:
    prefix = env.get("CREUSET_PREFIX", "")
    return {"network": f"{prefix}creuset-net", "mock": f"{prefix}mock-services",
            "proxy": f"{prefix}llm-proxy"}


def check_network(env: Dict[str, str]) -> Check:
    name = _names(env)["network"]
    proc = _docker(["network", "inspect", name, "--format", "{{.Internal}}"])
    if proc is None or proc.returncode != 0:
        return Check("stack", "sandbox network", FAIL, f"{name} does not exist",
                     "docker compose up -d llm-proxy mock-services")
    if proc.stdout.strip() != "true":
        return Check("stack", "sandbox network", FAIL,
                     f"{name} is NOT internal: agents under test could reach the internet",
                     f"docker compose down && docker network rm {name} && docker compose up -d llm-proxy mock-services")
    return Check("stack", "sandbox network", OK, f"{name} is internal")


def check_containers(env: Dict[str, str]) -> List[Check]:
    out = []
    for key in ("proxy", "mock"):
        name = _names(env)[key]
        proc = _docker(["inspect", name, "--format",
                        "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}"])
        state = proc.stdout.strip() if proc is not None and proc.returncode == 0 else ""
        if not state.startswith("running") or "unhealthy" in state or "starting" in state:
            hint = f"docker compose up -d {key == 'proxy' and 'llm-proxy' or 'mock-services'}"
            if key == "proxy" and state:
                hint += f"   (if it keeps restarting: docker logs {name})"
            out.append(Check("stack", name, FAIL, state or "not created", hint))
        else:
            out.append(Check("stack", name, OK, state))
    return out


def _image_created(image: str) -> Optional[float]:
    proc = _docker(["image", "inspect", image, "--format", "{{.Created}}"])
    if proc is None or proc.returncode != 0:
        return None
    raw = proc.stdout.strip()
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?(Z|[+-]\d\d:\d\d)$", raw)
    if not m:
        return None
    frac = (m.group(2) or ".0")[:7]   # datetime takes microseconds at most
    tz = "+00:00" if m.group(3) == "Z" else m.group(3)
    return datetime.fromisoformat(m.group(1) + frac + tz).timestamp()


def _newest_source(paths: List[Path]) -> Tuple[float, Optional[Path]]:
    newest, which = 0.0, None
    for base in paths:
        files = [base] if base.is_file() else [p for p in base.rglob("*") if p.is_file()]
        for f in files:
            if "__pycache__" in f.parts or "live_traffic" in f.parts:
                continue
            mtime = f.stat().st_mtime
            if mtime > newest:
                newest, which = mtime, f
    return newest, which


def built_images(env: Dict[str, str], root: Path = ROOT) -> List[Tuple[str, str, str, List[Path], bool]]:
    """(image, label, rebuild command, build inputs, needed for gate runs)."""
    deploy = root / "deploy"
    return [
        (env.get("AGENT_IMAGE_TAG") or "creuset-agent:latest", "bundled agent",
         "docker compose build agent-blue", [root / "agent"], not env.get("CREUSET_AGENT_IMAGE")),
        ("creuset-mock-services:latest", "mock-services", "docker compose build mock-services",
         [root / "sandbox" / "mock_services"], True),
        ("creuset-router:latest", "router", "docker compose build router",
         [deploy / "router.py", deploy / "Dockerfile.router", deploy / "requirements.router.txt",
          deploy / "constraints.router.txt"], False),
    ]


def check_images(env: Dict[str, str], root: Path = ROOT) -> List[Check]:
    """
    Present, and not older than the source they are built from. A stale image is
    the classic silent failure here: the router once ignored its state file for
    half a session because its image predated the fix.
    """
    out = []
    for image, label, rebuild, inputs, needed in built_images(env, root):
        created = _image_created(image)
        if created is None:
            out.append(Check("images", label, FAIL if needed else WARN, f"{image} not built",
                             rebuild + ("" if needed else "   (only needed for blue/green)")))
            continue
        newest, which = _newest_source(inputs)
        if newest > created + 1:
            rel = which.relative_to(root) if which else "?"
            out.append(Check("images", label, WARN, f"{image} is older than {rel}: it may not contain "
                                                    f"your latest changes", rebuild))
        else:
            out.append(Check("images", label, OK, image))
    external = (env.get("CREUSET_AGENT_IMAGE") or "").strip()
    if external:
        proc = _docker(["image", "inspect", external, "--format", "{{.Id}}"])
        if proc is None or proc.returncode != 0:
            out.append(Check("images", "agent under test", FAIL, f"{external} not found locally",
                             f"docker pull {external}   (or build it)"))
        else:
            out.append(Check("images", "agent under test", OK, f"{external} ({proc.stdout.strip()[:19]})"))
    return out


def check_container_images(env: Dict[str, str]) -> List[Check]:
    """
    Each running container against the image its compose service names now. A
    rebuild does not touch running containers: the old mock-services keeps its
    old world semantics, the old llm-proxy its old config, until recreated.
    """
    prefix = env.get("CREUSET_PREFIX", "")
    agent = env.get("AGENT_IMAGE_TAG") or "creuset-agent:latest"
    expected = [  # (service, container, image it should run, needed for gate runs)
        ("llm-proxy", f"{prefix}llm-proxy", "nginx:1.31-alpine", True),
        ("mock-services", f"{prefix}mock-services", "creuset-mock-services:latest", True),
        ("agent-blue", f"{prefix}agent-blue", agent, False),
        ("agent-green", f"{prefix}agent-green", agent, False),
        ("router", f"{prefix}creuset-router", "creuset-router:latest", False),
    ]
    out = []
    for service, container, image, needed in expected:
        running = _docker(["inspect", container, "--format", "{{.Image}}"])
        if running is None or running.returncode != 0:
            continue   # not created: check_containers reports the ones that matter
        current = _docker(["image", "inspect", image, "--format", "{{.Id}}"])
        if current is None or current.returncode != 0 or running.stdout.strip() == current.stdout.strip():
            continue
        out.append(Check("stack", f"{container} image", FAIL if needed else WARN,
                         f"created from an older image than {image}: it still runs the old code",
                         f"docker compose up -d --force-recreate {service}"))
    return out


def check_state(root: Path = ROOT) -> Check:
    state = root / "deploy" / "state" / "state.json"
    if not state.exists():
        return Check("stack", "deploy state", OK, "fresh install (blue live, nothing staged)")
    try:
        data = json.loads(state.read_text(encoding="utf-8"))
        active = data.get("active", "blue")
    except (OSError, ValueError, AttributeError) as e:
        return Check("stack", "deploy state", FAIL, f"{state} is unreadable ({type(e).__name__}); "
                                                    f"the router answers 503", "Fix or remove the file")
    if active not in ("blue", "green"):
        return Check("stack", "deploy state", FAIL, f"names no known active slot ({active!r})",
                     "Fix or remove deploy/state/state.json")
    return Check("stack", "deploy state", OK, f"{active} is live")


# ── Opt-in: probe and online ──────────────────────────────────────────────────

def check_isolation() -> Check:
    sys.path.insert(0, str(ROOT / "sandbox"))
    try:
        from run_test import isolation_probe
        result = isolation_probe()
    except Exception as e:  # pylint: disable=broad-except - report, never crash the doctor
        return Check("stack", "isolation probe", FAIL, f"{type(e).__name__}: {e}")
    if result.get("ok"):
        return Check("stack", "isolation probe", OK,
                     "gateway reachable, other paths 403, no internet TCP, no DNS")
    detail = result.get("error") or json.dumps({k: v for k, v in result.items() if k != "ok"})
    return Check("stack", "isolation probe", FAIL, detail,
                 "docker compose up -d --force-recreate llm-proxy mock-services, then re-run")


# Python's default User-Agent is refused outright by some providers' CDNs
# (Groq/Cloudflare: 403, error 1010), which would read as a bad key.
USER_AGENT = "creuset-doctor/1"
_MODELS_PROBE = (
    "import sys, urllib.request, urllib.error\n"
    "try:\n"
    # anthropic-version: Anthropic's /v1/models requires it; other providers ignore it.
    "    req = urllib.request.Request(sys.argv[1], headers={'User-Agent': sys.argv[2],\n"
    "                                                   'anthropic-version': '2023-06-01'})\n"
    "    r = urllib.request.urlopen(req, timeout=20); print(r.status)\n"
    "except urllib.error.HTTPError as e: print(e.code)\n"
    "except Exception as e: print(type(e).__name__)\n"
)


_NGINX_ERROR = re.compile(r"\[(?:error|crit|alert|emerg)\] \d+#\d+: (?:\*\d+ )?(.*)")


def _proxy_error(container: str) -> Optional[str]:
    """
    The last error nginx logged, e.g. "api.groq.com could not be resolved".
    Its own words beat a guess: the same 502 means DNS, TLS or a refused
    connection, and each has a different fix.
    """
    proc = _docker(["logs", "--tail", "200", container])
    if proc is None:
        return None
    errors = [m.group(1) for line in (proc.stdout + proc.stderr).splitlines()
              if (m := _NGINX_ERROR.search(line))]
    # The client address and request after the reason add nothing here.
    return errors[-1].split(", client:")[0][:200] if errors else None


def check_gateway_online(env: Dict[str, str]) -> Check:
    """
    GET <AGENT_API_BASE>/models from inside the sandbox network, through
    llm-proxy: proves DNS, TLS and the key in one call that costs no tokens.
    """
    names = _names(env)
    inspect = _docker(["inspect", names["mock"], "--format", "{{.Image}}"])
    if inspect is None or inspect.returncode != 0:
        return Check("online", "LLM gateway", SKIP, "mock-services is not running")
    base = (env.get("AGENT_API_BASE") or "http://llm-proxy:11434/openai/v1").rstrip("/")
    proc = _docker(["run", "--rm", "--network", names["network"], "--read-only", "--cap-drop", "ALL",
                    "--security-opt", "no-new-privileges", "--entrypoint", "python",
                    inspect.stdout.strip(), "-c", _MODELS_PROBE, f"{base}/models", USER_AGENT], timeout=60)
    status = proc.stdout.strip().splitlines()[-1] if proc is not None and proc.stdout.strip() else "no answer"
    if status == "200":
        return Check("online", "LLM gateway", OK, "llm-proxy reached the provider and the key was accepted")
    hints = {"401": "the provider rejected LLM_API_KEY", "403": "llm-proxy refused the path (check "
             "LLM_ALLOWED_ENDPOINTS includes models) or the provider refused the key",
             "502": "llm-proxy could not reach or verify the upstream (DNS, TLS, LLM_UPSTREAM_HOST)",
             "404": "wrong AGENT_API_BASE path or LLM_UPSTREAM_PATH_PREFIX"}
    detail = f"GET {base}/models -> {status}: " + hints.get(status, "see the proxy's log")
    reason = _proxy_error(names["proxy"])
    if reason:
        detail += f". llm-proxy logged: {reason}"
    # Docker's networking can take a minute to settle after Docker Desktop
    # starts; a 502 then (DNS failing, connections refused) clears on its own.
    return Check("online", "LLM gateway", FAIL, detail,
                 f"docker logs {names['proxy']}   (just started Docker? wait a minute and re-run)")


def check_judge_online(env: Dict[str, str]) -> Check:
    """GET <JUDGE_API_BASE>/models from the host, with the key the judge would send."""
    sys.path.insert(0, str(ROOT / "judge"))
    try:
        from model_judge import JudgeConfigError, _resolve_endpoint
        base, key = _resolve_endpoint(env)   # the same rule the judge applies to its key
    except ImportError as e:
        return Check("online", "judge endpoint", SKIP, f"cannot load judge/model_judge.py ({e})")
    except JudgeConfigError as e:
        return Check("online", "judge endpoint", SKIP, str(e))
    base = base.rstrip("/")
    request = urllib.request.Request(f"{base}/models", headers={"Authorization": f"Bearer {key}",
                                                                "User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=20) as r:
            status = str(r.status)
    except urllib.error.HTTPError as e:
        status = str(e.code)
    except (urllib.error.URLError, OSError) as e:
        status = type(e).__name__
    if status == "200":
        return Check("online", "judge endpoint", OK, f"{base} accepted the judge's key")
    return Check("online", "judge endpoint", FAIL, f"GET {base}/models -> {status}",
                 "Check JUDGE_API_BASE and the judge's key (JUDGE_API_KEY, else LLM_API_KEY for a "
                 "remote base you named)")


# ── Runner ────────────────────────────────────────────────────────────────────

def run_checks(probe: bool = False, online: bool = False, root: Path = ROOT) -> List[Check]:
    env, present = load_env(root)
    checks: List[Check] = [check_python(), check_modules(), check_logs_writable(root),
                           check_env_file(present), *check_config(env), check_prefix(env)]
    if checks[-1].status == FAIL:
        return checks   # every Docker name below depends on the prefix
    docker = check_docker()
    checks.append(docker)
    if docker.status != OK:
        return checks
    steps: List[Callable[[], object]] = [
        check_compose, lambda: check_network(env), lambda: check_containers(env),
        lambda: check_images(env, root), lambda: check_container_images(env), lambda: check_state(root),
    ]
    for step in steps:
        result = step()
        checks.extend(result if isinstance(result, list) else [result])
    if probe:
        checks.append(check_isolation())
    if online:
        checks.extend([check_gateway_online(env), check_judge_online(env)])
    return checks


def _print(checks: List[Check]) -> None:
    marks = {OK: "✓", WARN: "!", FAIL: "✗", SKIP: "-"}
    try:
        from rich.console import Console
        from rich.table import Table
    except ImportError:
        for c in checks:
            print(f"{marks[c.status]} [{c.group}] {c.name}: {c.detail}" + (f"\n    fix: {c.fix}" if c.fix else ""))
        return
    colours = {OK: "green", WARN: "yellow", FAIL: "red", SKIP: "dim"}
    table = Table(title="Creuset doctor", show_lines=False)
    for col in ("", "Check", "Found", "Fix"):
        table.add_column(col, overflow="fold")
    for c in checks:
        colour = colours[c.status]
        table.add_row(f"[{colour}]{marks[c.status]}[/{colour}]", f"{c.group} · {c.name}", c.detail,
                      f"[bold]{c.fix}[/bold]" if c.fix and c.status != OK else "")
    Console().print(table)


def main(argv: List[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    unknown = [a for a in argv if a not in ("--probe", "--online", "--json", "-h", "--help")]
    if unknown or "-h" in argv or "--help" in argv:
        print(__doc__)
        return 2 if unknown else 0
    checks = run_checks(probe="--probe" in argv, online="--online" in argv)
    failed = [c for c in checks if c.status == FAIL]
    if "--json" in argv:
        print(json.dumps({"ok": not failed, "checks": [asdict(c) for c in checks]}, indent=2))
    else:
        _print(checks)
        warned = sum(c.status == WARN for c in checks)
        print(f"\n{len(failed)} failed, {warned} warning(s)."
              + ("" if failed else " Ready." if not warned else " Ready, with warnings.")
              + ("" if "--probe" in argv else " Add --probe to prove sandbox isolation.")
              + ("" if "--online" in argv else " Add --online to verify the keys (no tokens spent)."))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
