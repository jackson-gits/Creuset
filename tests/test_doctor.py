"""
`doctor` preflight (sandbox/doctor.py).

Every first-run failure the doctor exists for must come out as one plain line
with the right exit code, and the key must never come out at all. No test here
needs Docker, a key or quota: every `docker` call goes through a recording fake,
the judge's SDK call goes to an in-process transport, and the harness functions
the doctor reuses are stubbed.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest
from dotenv import dotenv_values
from typer.testing import CliRunner

import doctor
import run_test
from conftest import ROOT

IMAGE_ID = "sha256:" + "a" * 64
MOCK_IMAGE_ID = "sha256:" + "c" * 64
KEY = "gsk_" + "Q7r" * 16  # shaped like a real Groq key; must never be printed
DOCKER_DOWN = ("Cannot connect to the Docker daemon at unix:///var/run/docker.sock. "
               "Is the docker daemon running?")

GOOD_ENV = {
    "LLM_API_KEY": KEY,
    "LLM_UPSTREAM_HOST": "api.groq.com",
    "AGENT_MODEL": "openai/gpt-oss-20b",
    "AGENT_MAX_TOKENS": "400",
    "JUDGE_API_BASE": "https://api.groq.com/openai/v1",
    "JUDGE_MODEL": "openai/gpt-oss-120b",
}

# Everything the doctor or the modules it calls read from the environment.
_ENV_PREFIXES = ("LLM_", "AGENT_", "JUDGE_", "CREUSET_", "OPENAI_", "MOCK_")
_ENV_NAMES = ("ROUTER_HOST_PORT", "MAX_LLM_CALLS", "FINALIZER_MAX_TOKENS")


def _proc(stdout: str = "", returncode: int = 0, stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _llm_reply(status: Optional[int], body: Any = "", headers: Optional[Dict[str, str]] = None,
               **extra: Any) -> subprocess.CompletedProcess:
    """What the in-container LLM probe prints."""
    text = body if isinstance(body, str) else json.dumps(body)
    return _proc(json.dumps({"status": status, "headers": headers or {}, "body": text, **extra}) + "\n")


class FakeRun:
    """Answers the commands the doctor runs (all `docker ...`) and records each one."""

    def __init__(self, **answers: Any):
        self.calls: List[List[str]] = []
        self.answers: Dict[str, Any] = {
            "info": _proc("27.3.1\n"),
            "info-limits": _proc("true true\n"),
            "--version": _proc("Docker version 27.3.1, build ce12230\n"),
            "version": _proc("Engine containerd runc docker-init \n"),
            "compose": _proc("2.29.7\n"),
            "ps": _proc(""),
            "logs": _proc(""),
            "inspect-env": _proc(json.dumps([f"LLM_API_KEY={KEY}", "LLM_UPSTREAM_HOST=api.groq.com", "PATH=/bin"])),
            "inspect-image": _proc(MOCK_IMAGE_ID + "\n"),
            "image-inspect": _proc(MOCK_IMAGE_ID + "\n"),
            "exec-health": _proc(json.dumps({"status": "ok", "strict_runs": False})),
            "run-write": _proc("writable\n"),
            "run-llm": _llm_reply(200, {"choices": []}, {"x-ratelimit-remaining-requests": "998"}),
            "rm": _proc(""),
        }
        self.answers.update({k.replace("_", "-"): v for k, v in answers.items()})

    @staticmethod
    def key(cmd: List[str]) -> str:
        assert cmd[0] == "docker", cmd
        a = cmd[1:]
        if a[0] == "info":
            return "info-limits" if "MemoryLimit" in a[-1] else "info"
        if a[0] in ("--version", "version", "compose", "ps", "logs", "rm"):
            return a[0]
        if a[0] == "inspect":
            return "inspect-env" if "{{json .Config.Env}}" in a else "inspect-image"
        if a[:2] == ["image", "inspect"]:
            return "image-inspect"
        if a[0] == "exec":
            return "exec-health"
        if a[0] == "run":
            return "run-write" if any(arg.endswith(":/creuset-live") for arg in a) else "run-llm"
        raise AssertionError(f"unexpected docker call {cmd}")

    def __call__(self, cmd, timeout=30, input=None):
        self.calls.append(list(cmd))
        answer = self.answers[self.key(list(cmd))]
        if isinstance(answer, BaseException):
            raise answer
        if callable(answer):
            return answer(list(cmd))
        return answer

    def runs(self, kind: str) -> List[List[str]]:
        return [c for c in self.calls if self.key(c) == kind]


def _judge(problem: Optional[str] = None) -> SimpleNamespace:
    def check_config() -> None:
        if problem:
            raise RuntimeError(problem)
    return SimpleNamespace(JUDGE_MODEL="openai/gpt-oss-120b", check_config=check_config,
                           _resolve_endpoint=lambda: ("https://api.groq.com/openai/v1", KEY))


@pytest.fixture
def root(tmp_path: Path) -> Path:
    """A checkout: .env, the three bundled prompts and logs/live_traffic."""
    (tmp_path / ".env").write_text("".join(f"{k}={v}\n" for k, v in GOOD_ENV.items()), encoding="utf-8")
    (tmp_path / "agent").mkdir()
    shutil.copytree(ROOT / "agent" / "variants", tmp_path / "agent" / "variants")
    (tmp_path / "logs" / "live_traffic").mkdir(parents=True)
    return tmp_path


@pytest.fixture
def fake(monkeypatch) -> FakeRun:
    """Docker, the harness, ports and the judge all answering 'ready'."""
    for name in list(os.environ):
        if name.startswith(_ENV_PREFIXES) or name in _ENV_NAMES:
            monkeypatch.delenv(name, raising=False)
    run = FakeRun()
    monkeypatch.setattr(doctor, "_run", run)
    monkeypatch.setattr(doctor, "_port_busy", lambda port: False)
    monkeypatch.setattr(doctor, "_model_judge", lambda: _judge())
    monkeypatch.setattr(run_test, "preflight", lambda image=None: [])
    monkeypatch.setattr(run_test, "isolation_probe", lambda: {"ok": True})
    monkeypatch.setattr(run_test, "resolve_image", lambda image=None: (image or "creuset-agent:latest", IMAGE_ID))
    monkeypatch.setattr(run_test, "validate_variant", lambda variant, image=None: None)
    monkeypatch.setattr(run_test, "canary_warning", lambda variant, image=None: None)
    monkeypatch.setattr(run_test, "preflight_warnings", lambda: [])
    return run


def _ctx(root: Path, env: Optional[Dict[str, str]] = None, **kw: Any) -> doctor.Context:
    env = dict(GOOD_ENV if env is None else env)
    return doctor.Context(env=env, dotenv=dict(dotenv_values(root / ".env")) if (root / ".env").is_file() else {},
                          root=root, **kw)


def _by_name(checks: List[doctor.Check], name: str) -> List[doctor.Check]:
    return [c for c in checks if c.name == name]


def _one(checks: List[doctor.Check], name: str) -> doctor.Check:
    found = _by_name(checks, name)
    assert len(found) == 1, [(c.name, c.status, c.detail) for c in checks]
    return found[0]


def _all_text(checks: List[doctor.Check]) -> str:
    return "\n".join(f"{c.name} {c.detail} {c.fix or ''}" for c in checks)


# ── The acceptance criteria ───────────────────────────────────────────────────

def test_help_works_without_docker(tmp_path):
    """No docker on PATH, no .env: --help still answers (it touches nothing)."""
    env = {k: v for k, v in os.environ.items() if k not in ("DOCKER_HOST",)}
    env["PATH"] = str(tmp_path)  # an empty directory: there is no docker to find
    proc = subprocess.run([sys.executable, str(ROOT / "sandbox" / "doctor.py"), "--help"], env=env,
                          capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert "--llm" in proc.stdout and "--skip-model-judge" in proc.stdout


def test_env_example_copied_unchanged_exits_2_naming_the_placeholder(fake, root, monkeypatch):
    shutil.copy(ROOT / ".env.example", root / ".env")
    for name, value in dotenv_values(root / ".env").items():
        monkeypatch.setenv(name, value or "")
    monkeypatch.setattr(doctor, "_ROOT", root)
    result = CliRunner().invoke(doctor.app, [])
    assert result.exit_code == 2, result.output
    assert "LLM_API_KEY is still the placeholder 'your-key-here' (from .env)" in " ".join(result.output.split())


def test_no_docker_exits_2_with_dockers_own_error_line(fake, root):
    fake.answers["info"] = _proc(returncode=1, stderr=f"WARNING: bridge-nf-call-iptables is disabled\n{DOCKER_DOWN}\n")
    checks = doctor.run_checks(_ctx(root))
    docker = _one(checks, "docker")
    assert docker.status == doctor.FAIL and DOCKER_DOWN in docker.detail  # the daemon's words, not ours
    assert doctor.exit_code(checks) == 2
    # Nothing downstream repeats the failure or tries Docker again.
    assert all(c.status == doctor.SKIP for c in _by_name(checks, "infra") + _by_name(checks, "isolation"))
    assert not fake.runs("run-write") and not fake.runs("run-llm")


def test_docker_command_missing_is_a_config_problem(fake, root):
    fake.answers["info"] = FileNotFoundError("docker")
    fake.answers["compose"] = FileNotFoundError("docker")
    checks = doctor.run_checks(_ctx(root))
    assert "not on PATH" in _one(checks, "docker").detail
    assert doctor.exit_code(checks) == 2


def test_docker_socket_permission_gets_the_group_hint(fake, root):
    fake.answers["info"] = _proc(returncode=1, stderr="permission denied while trying to connect to the Docker "
                                                      "daemon socket at unix:///var/run/docker.sock")
    assert "docker group" in _one(doctor.check_docker(_ctx(root)), "docker").fix


def test_ready_setup_exits_0_and_calls_no_llm(fake, root):
    checks = doctor.run_checks(_ctx(root))
    assert doctor.exit_code(checks) == 0, _all_text(checks)
    assert not fake.runs("run-llm")  # no quota without --llm
    assert "--llm" in _one(checks, "LLM: agent").detail


# ── Configuration ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("placeholder", ["your-key-here", "ci-placeholder", "sandbox-placeholder-key"])
def test_known_placeholder_key_is_named(fake, root, placeholder):
    check = doctor.check_llm_key(_ctx(root, {**GOOD_ENV, "LLM_API_KEY": placeholder}))[0]
    assert check.status == doctor.FAIL and f"'{placeholder}'" in check.detail


def test_placeholder_like_key_is_refused_without_printing_it(fake, root):
    value = "my-groq-placeholder-0042"
    check = doctor.check_llm_key(_ctx(root, {**GOOD_ENV, "LLM_API_KEY": value}))[0]
    assert check.status == doctor.FAIL and value not in check.detail


def test_missing_key(fake, root):
    env = {k: v for k, v in GOOD_ENV.items() if k != "LLM_API_KEY"}
    assert doctor.check_llm_key(_ctx(root, env))[0].status == doctor.FAIL


@pytest.mark.parametrize("value", [f'"{KEY}"', f"{KEY} ", f"{KEY}$x"])
def test_key_with_characters_llm_proxy_refuses(fake, root, value):
    check = doctor.check_llm_key(_ctx(root, {**GOOD_ENV, "LLM_API_KEY": value}))[0]
    assert check.status == doctor.FAIL and "llm-proxy refuses" in check.detail
    assert KEY not in check.detail


def test_real_key_is_accepted_and_never_shown(fake, root):
    checks = doctor.check_llm_key(_ctx(root))
    assert [c.status for c in checks] == [doctor.OK]
    assert KEY not in _all_text(checks) and "from .env" in checks[0].detail


def test_key_for_another_provider_warns(fake, root):
    checks = doctor.check_llm_key(_ctx(root, {**GOOD_ENV, "LLM_UPSTREAM_HOST": "api.openai.com"}))
    assert [c.status for c in checks] == [doctor.OK, doctor.WARN]
    assert "Groq key" in checks[1].detail


def test_placeholder_is_fine_for_a_keyless_http_gateway(fake, root):
    env = {**GOOD_ENV, "LLM_API_KEY": "ci-placeholder", "LLM_UPSTREAM_SCHEME": "http", "LLM_UPSTREAM_HOST": "ollama"}
    assert doctor.check_llm_key(_ctx(root, env))[0].status == doctor.OK


def test_no_env_file(fake, tmp_path):
    assert doctor.check_env_file(_ctx(tmp_path, {}))[0].status == doctor.FAIL
    # CI: everything comes from the environment.
    assert doctor.check_env_file(_ctx(tmp_path))[0].status == doctor.WARN


def test_agent_model_unset_and_harness_warnings(fake, root, monkeypatch):
    monkeypatch.setattr(run_test, "preflight_warnings", lambda: ["AGENT_MAX_TOKENS is not set"])
    env = {k: v for k, v in GOOD_ENV.items() if k != "AGENT_MODEL"}
    checks = doctor.check_agent_settings(_ctx(root, env))
    assert [(c.name, c.status) for c in checks] == [("AGENT_MODEL", doctor.FAIL), ("agent settings", doctor.WARN)]


@pytest.mark.parametrize("base, upstream, status, phrase", [
    (None, "api.groq.com", doctor.OK, "llm-proxy"),
    ("http://llm-proxy:11434/v1", "api.openai.com", doctor.OK, "api.openai.com"),
    ("http://llm-proxy:11434/api/v1", "api.groq.com", doctor.FAIL, "403"),
    ("https://llm-proxy:11434/openai/v1", "api.groq.com", doctor.FAIL, "plain http"),
    ("http://llm-proxy:11434/v1", "api.groq.com", doctor.WARN, "/openai/v1"),
    ("http://llm-proxy:11434/openai/v1", "api.openai.com", doctor.WARN, "/v1"),
    ("http://my-gateway:4000/v1", "api.groq.com", doctor.WARN, "not llm-proxy"),
])
def test_agent_route(fake, root, base, upstream, status, phrase):
    env = {**GOOD_ENV, "LLM_UPSTREAM_HOST": upstream, **({"AGENT_API_BASE": base} if base else {})}
    check = doctor.check_agent_route(_ctx(root, env))[0]
    assert check.status == status and phrase in check.detail + (check.fix or "")


def test_judge_settings(fake, root, monkeypatch):
    assert doctor.check_judge_config(_ctx(root, judge=False))[0].status == doctor.SKIP
    monkeypatch.setattr(doctor, "_model_judge", lambda: _judge("JUDGE_API_BASE is not set."))
    check = doctor.check_judge_config(_ctx(root))[0]
    assert check.status == doctor.FAIL and check.detail == "JUDGE_API_BASE is not set."
    assert "--skip-model-judge" in check.fix


def test_judge_settings_use_model_judge_check_config(fake, root, monkeypatch):
    """The real model_judge, not a copy of its rules."""
    import model_judge
    monkeypatch.setattr(doctor, "_model_judge", lambda: model_judge)
    monkeypatch.setattr(model_judge, "JUDGE_MODEL", "openai/gpt-oss-120b")
    monkeypatch.delenv("JUDGE_API_BASE", raising=False)
    check = doctor.check_judge_config(_ctx(root))[0]
    assert check.status == doctor.FAIL and "JUDGE_API_BASE is not set" in check.detail


@pytest.mark.parametrize("version, status", [
    ("2.23.3\n", doctor.FAIL), ("2.24.0\n", doctor.OK), ("v2.29.7\n", doctor.OK), ("5.6.0\n", doctor.OK),
    ("garbled\n", doctor.WARN),
])
def test_compose_version(fake, root, version, status):
    fake.answers["compose"] = _proc(version)
    assert doctor.check_compose(_ctx(root))[0].status == status


def test_compose_plugin_missing(fake, root):
    fake.answers["compose"] = _proc(returncode=1, stderr="docker: 'compose' is not a docker command.")
    check = doctor.check_compose(_ctx(root))[0]
    assert check.status == doctor.FAIL and "'compose' is not a docker command" in check.detail


def test_unenforced_resource_limits_and_podman_warn(fake, root):
    fake.answers["info-limits"] = _proc("true false\n")
    fake.answers["--version"] = _proc("podman version 5.2.0\n")
    checks = doctor.check_docker(_ctx(root))
    text = _all_text(checks)
    assert "--pids-limit" in text and "LLM_PROXY_RESOLVER=local" in text
    assert [c.status for c in checks] == [doctor.OK, doctor.WARN, doctor.WARN]


# ── Ports ─────────────────────────────────────────────────────────────────────

def test_port_busy_sees_a_listener():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        assert doctor._port_busy(port)
    assert not doctor._port_busy(port)


def test_ports(fake, root, monkeypatch):
    monkeypatch.setattr(doctor, "_port_busy", lambda port: port in (9000, 8090))
    monkeypatch.setattr(doctor, "_is_creuset_ui", lambda port: False)
    ctx = _ctx(root, {**GOOD_ENV, "ROUTER_HOST_PORT": "9000"}, docker_ok=True)
    fake.answers["ps"] = _proc("creuset-router\n")
    checks = doctor.check_ports(ctx)
    assert [(c.name, c.status) for c in checks] == [("port 9000", doctor.OK), ("port 8090", doctor.WARN)]
    assert "publish=9000" in fake.runs("ps")[0]

    fake.answers["ps"] = _proc("someone-elses-app\n")
    assert doctor.check_ports(ctx)[0].status == doctor.WARN
    assert doctor.check_ports(_ctx(root, {**GOOD_ENV, "ROUTER_HOST_PORT": "http"}))[0].status == doctor.FAIL


# ── Infrastructure ────────────────────────────────────────────────────────────

def test_infra_problems_are_reported_once_each(fake, root, monkeypatch):
    image_problem = "Agent image 'creuset-agent:latest' not found (no such image). Build it: docker compose build agent-blue"

    def missing(image=None):
        raise RuntimeError(image_problem)
    monkeypatch.setattr(run_test, "resolve_image", missing)
    monkeypatch.setattr(run_test, "preflight", lambda image=None: [
        "AGENT_MODEL is not set. Put it in .env", "Network 'creuset-net' missing — run: docker compose up -d",
        image_problem])
    checks = doctor.check_infra(_ctx(root, docker_ok=True))
    assert [(c.name, c.status) for c in checks] == [("agent image", doctor.FAIL), ("infra", doctor.FAIL)]
    assert "creuset-net" in checks[1].detail


def test_refused_llm_proxy_shows_its_own_reason(fake, root, monkeypatch):
    monkeypatch.setattr(run_test, "preflight", lambda image=None: [
        "Container 'llm-proxy' not healthy (exited) — run: docker compose up -d llm-proxy"])
    fake.answers["logs"] = _proc("", stderr=(
        "05-creuset-validate.envsh: ERROR: LLM_UPSTREAM_SCHEME must be https or http, not 'ftp'.\n"
        "05-creuset-validate.envsh: refusing to start llm-proxy, which holds the real API key.\n"))
    ctx = _ctx(root, docker_ok=True)
    check = _one(doctor.check_infra(ctx), "infra")
    assert "LLM_UPSTREAM_SCHEME must be https or http, not 'ftp'" in check.fix
    assert not ctx.infra_ok


def test_running_llm_proxy_with_an_old_key_is_caught_without_showing_either(fake, root):
    old = "gsk_" + "Z9" * 24
    fake.answers["inspect-env"] = _proc(json.dumps([f"LLM_API_KEY={old}", "LLM_UPSTREAM_HOST=api.groq.com"]))
    check = doctor.check_proxy_settings(_ctx(root, infra_ok=True))[0]
    assert check.status == doctor.FAIL and "LLM_API_KEY" in check.detail and "force-recreate" in check.fix
    assert old not in check.detail and KEY not in check.detail

    fake.answers["inspect-env"] = _proc(json.dumps([f"LLM_API_KEY={KEY}", "LLM_UPSTREAM_HOST=api.groq.com"]))
    assert doctor.check_proxy_settings(_ctx(root, infra_ok=True))[0].status == doctor.OK


def test_stale_mock_services_image_warns(fake, root):
    fake.answers["exec-health"] = _proc(json.dumps({"status": "ok", "service": "creuset-mock-services"}))
    check = doctor.check_mock_services(_ctx(root, infra_ok=True))[0]
    assert check.status == doctor.WARN and "docker compose build mock-services" in check.fix


def test_isolation_failure_says_what_leaked(fake, root, monkeypatch):
    monkeypatch.setattr(run_test, "isolation_probe", lambda: {
        "ok": False, "llm_proxy_health": 200, "llm_proxy_other_path": 403, "mock_services_health": 200,
        "internet_tcp_1_1_1_1": "connected", "internet_dns_example_com": "gaierror"})
    check = doctor.check_isolation(_ctx(root, infra_ok=True))[0]
    assert check.status == doctor.FAIL and "reached the internet" in check.detail
    assert doctor.check_isolation(_ctx(root))[0].status == doctor.SKIP


# ── Live traffic ──────────────────────────────────────────────────────────────

def test_live_traffic_is_written_from_a_container_as_the_slot_uid(fake, root):
    checks = doctor.check_live_traffic(_ctx(root, {**GOOD_ENV, "CREUSET_UID": "1000"}, docker_ok=True))
    assert checks[0].status == doctor.OK
    cmd = fake.runs("run-write")[0]
    assert cmd[cmd.index("--user") + 1] == "1000:10001"
    assert cmd[cmd.index("--network") + 1] == "none"
    assert cmd[cmd.index("--cap-drop") + 1] == "ALL"  # as the slots run: no root override of the bits
    assert MOCK_IMAGE_ID in cmd and "--rm" in cmd
    assert cmd[cmd.index("--name") + 1].startswith("creuset-doctor-")
    assert f"{(root / 'logs' / 'live_traffic').resolve().as_posix()}:/creuset-live" in cmd


def test_unwritable_live_traffic_warns_with_the_fix(fake, root):
    fake.answers["run-write"] = _proc("denied: Permission denied\n")
    check = doctor.check_live_traffic(_ctx(root, docker_ok=True))[0]
    assert check.status == doctor.WARN and "CREUSET_UID" in check.fix and "Gate runs are not affected" in check.detail


def test_missing_live_traffic_dir_is_not_created_by_docker(fake, root):
    shutil.rmtree(root / "logs" / "live_traffic")
    check = doctor.check_live_traffic(_ctx(root, docker_ok=True))[0]
    assert check.status == doctor.WARN and check.fix == "mkdir logs/live_traffic"
    assert not fake.runs("run-write")  # a bind mount would have created it as root


def test_bad_slot_uid(fake, root):
    assert doctor.check_live_traffic(_ctx(root, {**GOOD_ENV, "CREUSET_UID": "me"}))[0].status == doctor.FAIL


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="host permission bits are a Linux fallback")
def test_live_traffic_host_permissions_without_docker(fake, root):
    directory = root / "logs" / "live_traffic"
    directory.chmod(0o755)
    own = {**GOOD_ENV, "CREUSET_UID": str(os.getuid()), "CREUSET_GID": str(os.getgid())}
    assert doctor.check_live_traffic(_ctx(root, own))[0].status == doctor.OK
    other = {**GOOD_ENV, "CREUSET_UID": str(os.getuid() + 4242), "CREUSET_GID": str(os.getgid() + 4242)}
    check = doctor.check_live_traffic(_ctx(root, other))[0]
    assert check.status == doctor.WARN and "mode 755" in check.detail
    assert not fake.runs("run-write")


# ── Variants and canary ───────────────────────────────────────────────────────

def test_every_bundled_variant_is_checked(fake, root):
    checks = doctor.check_variants(_ctx(root, docker_ok=True, image_id=IMAGE_ID))
    assert [c.name for c in checks] == ["variant broken", "variant hardened", "variant naive"]
    assert all(c.status == doctor.OK and "matches the copy inside the image" in c.detail for c in checks)


def test_stale_image_and_missing_canary(fake, root, monkeypatch):
    stale = "agent/variants/hardened.txt differs from the copy inside image ... Rebuild it: docker compose build agent-blue"
    monkeypatch.setattr(run_test, "validate_variant", lambda v, image=None: stale if v == "hardened" else None)
    monkeypatch.setattr(run_test, "canary_warning", lambda v, image=None: "no canary marker" if v == "naive" else None)
    checks = doctor.check_variants(_ctx(root, variants=["hardened", "naive"], docker_ok=True, image_id=IMAGE_ID))
    assert [(c.name, c.status) for c in checks] == [
        ("variant hardened", doctor.FAIL), ("variant naive", doctor.OK), ("variant naive", doctor.WARN)]
    assert checks[0].detail == stale


def test_custom_image_variants_are_opaque(fake, root, monkeypatch):
    monkeypatch.setattr(run_test, "is_bundled_image", lambda image_id: False)
    checks = doctor.check_variants(_ctx(root, image="acme/agent:1.4", docker_ok=True))
    assert [c.status for c in checks] == [doctor.SKIP] and "CREUSET_CANARY" in checks[0].detail
    named = doctor.check_variants(_ctx(root, image="acme/agent:1.4", variants=["prod"], docker_ok=True))
    assert named[0].status == doctor.OK and "as-is" in named[0].detail


def test_empty_canary_setting_warns(fake, root):
    checks = doctor.check_variants(_ctx(root, {**GOOD_ENV, "CREUSET_CANARY": ""}, docker_ok=True, image_id=IMAGE_ID))
    assert _by_name(checks, "canary")[0].status == doctor.WARN


# ── --llm: the agent's route ──────────────────────────────────────────────────

def test_agent_probe_runs_in_the_mock_services_image_on_the_sandbox_network(fake, root):
    checks = doctor.check_agent_llm(_ctx(root, llm=True, docker_ok=True, infra_ok=True))
    assert checks[0].status == doctor.OK and "x-ratelimit-remaining-requests=998" in checks[0].detail
    cmd = fake.runs("run-llm")[0]
    image_at = cmd.index("--entrypoint") + 2
    assert cmd[image_at] == MOCK_IMAGE_ID and IMAGE_ID not in cmd  # not the agent image
    assert cmd[cmd.index("--network") + 1] == run_test.NETWORK
    assert cmd[cmd.index("--name") + 1].startswith("creuset-doctor-") and "--rm" in cmd
    assert "creuset.project=creuset" in cmd
    assert cmd[image_at + 3:image_at + 5] == ["http://llm-proxy:11434/openai/v1/chat/completions", "openai/gpt-oss-20b"]
    assert not any(KEY in arg for arg in cmd)  # llm-proxy holds the key, never the probe
    assert '"max_tokens": 1' in cmd[image_at + 2]


def test_agent_probe_is_removed_after_a_timeout(fake, root):
    fake.answers["run-llm"] = subprocess.TimeoutExpired("docker", 90)
    check = doctor.check_agent_llm(_ctx(root, llm=True, infra_ok=True))[0]
    name = fake.runs("run-llm")[0][fake.runs("run-llm")[0].index("--name") + 1]
    assert ["docker", "rm", "-f", name] in fake.calls
    assert check.status == doctor.FAIL and check.kind == doctor.PROVIDER


def test_agent_probe_needs_the_infra(fake, root):
    assert doctor.check_agent_llm(_ctx(root, llm=True))[0].status == doctor.SKIP
    assert not fake.runs("run-llm")


_CERT = ("2026/10/14 07:58:39 [error] 46#46: *21 upstream SSL certificate verify error: (20:unable to get local "
         "issuer certificate) while SSL handshaking to upstream, client: 172.18.0.4, server: , request: \"POST\"")
_DNS = "2026/10/14 07:58:39 [error] 46#46: *3 api.groq.com could not be resolved (3: Host not found), client: x"
_CONNECT = "2026/10/14 07:58:39 [error] 46#46: *3 connect() failed (111: Connection refused) while connecting"


@pytest.mark.parametrize("reply, logs, status, kind, phrase", [
    (_llm_reply(401, {"error": {"message": "Invalid API Key"}}), "", doctor.FAIL, doctor.CONFIG,
     "force-recreate llm-proxy"),
    (_llm_reply(403, "creuset llm-proxy: egress denied\n"), "", doctor.FAIL, doctor.CONFIG, "LLM_ALLOWED_ENDPOINTS"),
    (_llm_reply(403, {"error": {"message": "Forbidden"}}), "", doctor.FAIL, doctor.CONFIG, "permissions"),
    (_llm_reply(404, {"error": {"message": "The model `x` does not exist", "code": "model_not_found"}}), "",
     doctor.FAIL, doctor.CONFIG, "AGENT_MODEL"),
    (_llm_reply(404, "Not Found"), "", doctor.FAIL, doctor.CONFIG, "LLM_UPSTREAM_PATH_PREFIX"),
    (_llm_reply(429, {"error": {"message": "Rate limit reached: tokens per day (TPD)"}},
                {"x-ratelimit-remaining-tokens": "0", "retry-after": "421"}), "", doctor.FAIL, doctor.PROVIDER,
     "x-ratelimit-remaining-tokens=0"),
    (_llm_reply(502, "Bad Gateway"), _CERT, doctor.FAIL, doctor.CONFIG, "LLM_PROXY_EXTRA_CA_FILE"),
    (_llm_reply(502, "Bad Gateway"), _DNS, doctor.FAIL, doctor.CONFIG, "LLM_PROXY_RESOLVER=local"),
    (_llm_reply(502, "Bad Gateway"), _CONNECT, doctor.FAIL, doctor.PROVIDER, "connect() failed"),
    (_llm_reply(503, {"error": {"message": "over capacity"}}), "", doctor.FAIL, doctor.PROVIDER, "over capacity"),
    (_llm_reply(400, {"error": {"message": "Unsupported parameter: 'max_tokens'"}}), "", doctor.WARN, None,
     "max_tokens"),
    (_llm_reply(None, error="URLError: <urlopen error [Errno -2] Name or service not known>"), "", doctor.FAIL,
     doctor.CONFIG, "could not reach llm-proxy"),
])
def test_agent_probe_advice(fake, root, reply, logs, status, kind, phrase):
    fake.answers["run-llm"] = reply
    fake.answers["logs"] = _proc("", stderr=logs)
    check = doctor.check_agent_llm(_ctx(root, llm=True, infra_ok=True))[0]
    assert (check.status, check.kind) == (status, kind)
    assert phrase in f"{check.detail} {check.fix}"
    assert "client: 172" not in check.detail  # nginx's preamble and trailer are trimmed


def test_quota_exhausted_exits_3_and_config_problems_win(fake, root):
    fake.answers["run-llm"] = _llm_reply(429, {"error": {"message": "Rate limit reached"}})
    checks = doctor.run_checks(_ctx(root, llm=True, judge=False))
    assert doctor.exit_code(checks) == 3, _all_text(checks)
    broken = doctor.run_checks(_ctx(root, {**GOOD_ENV, "LLM_API_KEY": "your-key-here"}, llm=True, judge=False))
    assert doctor.exit_code(broken) == 2


# ── --llm: the judge's route ──────────────────────────────────────────────────

@pytest.fixture
def judge_transport(monkeypatch):
    """The judge probe's real SDK call, answered in-process."""
    import httpx
    import openai

    seen: List[httpx.Request] = []
    replies: List[httpx.Response] = []
    real = openai.OpenAI

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return replies[0]

    monkeypatch.setattr(openai, "OpenAI", lambda **kw: real(**kw, http_client=httpx.Client(
        transport=httpx.MockTransport(handler))))
    return SimpleNamespace(seen=seen, replies=replies)


def test_judge_probe_makes_one_call_with_the_judges_key(fake, root, judge_transport):
    import httpx
    judge_transport.replies.append(httpx.Response(429, json={"error": {"message": "Rate limit: org_01abcXYZ"}},
                                                  headers={"x-ratelimit-remaining-requests": "0"}))
    checks = doctor.check_judge_llm(_ctx(root, llm=True, judge_ok=True))
    assert len(judge_transport.seen) == 1  # no retries: a 429 is the answer
    request = judge_transport.seen[0]
    assert request.headers["authorization"] == f"Bearer {KEY}"
    assert json.loads(request.content)["max_tokens"] == 1
    assert checks[0].status == doctor.FAIL and checks[0].kind == doctor.PROVIDER
    assert "x-ratelimit-remaining-requests=0" in checks[0].detail


def test_judge_probe_tls_failure_is_a_config_problem(fake, root, monkeypatch):
    monkeypatch.setattr(doctor, "_judge_llm_request", lambda: {
        "status": None, "error": "SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify "
                                 "failed: unable to get local issuer certificate"})
    check = doctor.check_judge_llm(_ctx(root, llm=True, judge_ok=True))[0]
    assert (check.status, check.kind) == (doctor.FAIL, doctor.CONFIG) and "SSL_CERT_FILE" in check.fix


def test_judge_probe_is_skippable(fake, root, monkeypatch):
    called: List[bool] = []
    monkeypatch.setattr(doctor, "_judge_llm_request", lambda: called.append(True) or {"status": 200})
    assert doctor.check_judge_llm(_ctx(root, llm=True, judge_ok=True, judge_call=False))[0].status == doctor.SKIP
    assert doctor.check_judge_llm(_ctx(root, llm=True, judge_ok=False))[0].status == doctor.SKIP
    assert doctor.check_judge_llm(_ctx(root, llm=True, judge=False)) == []
    assert not called


# ── Output, redaction and exit codes ──────────────────────────────────────────

def test_keys_and_account_ids_are_redacted_everywhere(fake, root, monkeypatch):
    # A misbehaving provider or proxy echoing the key: it still must not reach the screen.
    fake.answers["run-llm"] = _llm_reply(401, {"error": {"message": f"Invalid API Key {KEY} for org_01hzzq"}})
    monkeypatch.setattr(run_test, "preflight", lambda image=None: [])
    checks = doctor.run_checks(_ctx(root, llm=True, judge=False))
    text = _all_text(checks)
    assert KEY not in text and "org_01hzzq" not in text and "[REDACTED]" in text


def test_a_crashing_check_fails_closed_instead_of_a_traceback(fake, root, monkeypatch):
    def boom(*_a, **_k):
        raise ValueError("unexpected")
    monkeypatch.setattr(run_test, "isolation_probe", boom)
    checks = doctor.run_checks(_ctx(root, infra_ok=True))
    crashed = _one(checks, "isolation")
    assert crashed.status == doctor.FAIL and "ValueError: unexpected" in crashed.detail
    assert doctor.exit_code(checks) == 2


def test_exit_codes():
    ok = doctor.ok("a", "")
    provider = doctor.fail("b", "", kind=doctor.PROVIDER)
    config = doctor.fail("c", "")
    warning = doctor.warn("d", "")
    assert doctor.exit_code([ok, warning]) == 0
    assert doctor.exit_code([ok, warning], strict=True) == 2
    assert doctor.exit_code([ok, provider]) == 3
    assert doctor.exit_code([provider, config]) == 2


def test_json_output(fake, root, monkeypatch):
    for name, value in GOOD_ENV.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(doctor, "_ROOT", root)
    result = CliRunner().invoke(doctor.app, ["--json", "--skip-model-judge"])
    assert result.exit_code == 0, result.output
    text = result.stdout
    report = json.loads(text[text.index('{\n  "schema_version"'):])
    assert report["exit_code"] == 0 and report["ready"] is True
    assert {c["name"] for c in report["checks"]} >= {"python", "LLM_API_KEY", "docker", "compose", "infra"}
    assert KEY not in result.output


def test_every_helper_container_is_named_and_labelled_for_cleanup(fake, root):
    doctor.run_checks(_ctx(root, llm=True, judge=False))
    runs = [c for c in fake.calls if c[1] == "run"]
    assert len(runs) == 2  # the live-traffic write and the LLM probe
    for cmd in runs:
        assert "--rm" in cmd and cmd[cmd.index("--name") + 1].startswith("creuset-doctor-")
        assert "creuset.project=creuset" in cmd and any(a.startswith("creuset.run=creuset-doctor-") for a in cmd)


def test_build_context_reads_dotenv_for_sources(root, monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "gsk_" + "other" * 8)
    ctx = doctor.build_context(image=None, variants=[], llm=False, judge=True, judge_call=True, root=root)
    assert ctx.dotenv["LLM_API_KEY"] == KEY
    assert doctor._source(ctx, "LLM_API_KEY") == "the environment, which overrides .env"
