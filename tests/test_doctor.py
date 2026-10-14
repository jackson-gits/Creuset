"""scripts/doctor.py: says what is wrong, how to fix it, and never prints a secret."""

import json
import os
import subprocess
import sys
import time

import pytest

from conftest import ROOT, load_module

doctor = load_module("doctor", ROOT / "scripts" / "doctor.py")
SECRET = "gsk_" + "s3cr3t" * 8


def _proc(stdout="", returncode=0):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


@pytest.fixture
def fake_docker(monkeypatch):
    answers = {}

    def fake(args, timeout=30):
        for prefix, proc in answers.items():
            if " ".join(args).startswith(prefix):
                return proc
        return _proc(returncode=1)
    monkeypatch.setattr(doctor, "_docker", fake)
    return answers


def test_env_file_parsing(tmp_path):
    (tmp_path / ".env").write_text(
        "# comment\nexport A=1\nB='two words'\nC=\"x\"\nD=val # trailing comment\nnot a line\n",
        encoding="utf-8")
    assert doctor._parse_env_file(tmp_path / ".env") == {"A": "1", "B": "two words", "C": "x", "D": "val"}


def test_real_environment_overrides_the_env_file(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("AGENT_MODEL=from-file\n", encoding="utf-8")
    monkeypatch.setenv("AGENT_MODEL", "from-env")
    env, present = doctor.load_env(tmp_path)
    assert present and env["AGENT_MODEL"] == "from-env"


@pytest.mark.parametrize("key, status", [("", "fail"), ("your-key-here", "fail"), (SECRET, "ok")])
def test_api_key_is_checked_but_never_printed(key, status):
    checks = doctor.check_config({"LLM_API_KEY": key, "AGENT_MODEL": "m", "LLM_UPSTREAM_HOST": "h"})
    api = next(c for c in checks if c.name == "LLM_API_KEY")
    assert api.status == status
    assert SECRET not in json.dumps([c.__dict__ for c in checks])


def test_judge_key_rules_are_the_judges_own():
    """A Groq key aimed at another provider is refused by the judge, so the doctor says so."""
    check = doctor.check_judge_config({"JUDGE_MODEL": "m", "JUDGE_API_BASE": "https://api.example.com/v1",
                                       "LLM_API_KEY": SECRET})
    assert check.status == "warn" and "Groq key" in check.detail
    assert SECRET not in check.detail


def test_a_bad_prefix_stops_before_any_docker_name_is_built(monkeypatch, tmp_path):
    monkeypatch.setenv("CREUSET_PREFIX", "Bad Prefix")
    monkeypatch.setattr(doctor, "check_docker", lambda: pytest.fail("must stop first"))
    checks = doctor.run_checks(root=tmp_path)
    assert checks[-1].name == "CREUSET_PREFIX" and checks[-1].status == "fail"


@pytest.mark.parametrize("output, status", [("2.23.0", "fail"), ("v2.24.0", "ok"), ("5.4.0", "ok"), ("", "fail")])
def test_compose_version(fake_docker, output, status):
    fake_docker["compose version"] = _proc(output)
    assert doctor.check_compose().status == status


def test_a_network_that_is_not_internal_fails(fake_docker):
    fake_docker["network inspect"] = _proc("false\n")
    check = doctor.check_network({})
    assert check.status == "fail" and "NOT internal" in check.detail


def test_names_follow_the_prefix(fake_docker):
    fake_docker["network inspect ci-creuset-net"] = _proc("true\n")
    assert doctor.check_network({"CREUSET_PREFIX": "ci-"}).status == "ok"


def test_a_stale_image_is_a_warning_with_the_rebuild_command(fake_docker, tmp_path, monkeypatch):
    for sub in ("agent", "sandbox/mock_services", "deploy"):
        (tmp_path / sub).mkdir(parents=True)
    (tmp_path / "agent" / "run_agent.py").write_text("x", encoding="utf-8")
    (tmp_path / "sandbox" / "mock_services" / "main.py").write_text("x", encoding="utf-8")
    long_ago = time.time() - 3600
    os.utime(tmp_path / "sandbox" / "mock_services" / "main.py", (long_ago, long_ago))
    # Every image was built 10 minutes ago: after main.py, before run_agent.py.
    built = time.strftime("%Y-%m-%dT%H:%M:%S.123456789Z", time.gmtime(time.time() - 600))
    fake_docker["image inspect"] = _proc(built + "\n")
    checks = {c.name: c for c in doctor.check_images({}, tmp_path)}
    assert checks["bundled agent"].status == "warn"
    assert checks["bundled agent"].fix == "docker compose build agent-blue"
    assert checks["mock-services"].status == "ok"


def test_a_missing_mock_services_image_fails_but_router_only_warns(fake_docker, tmp_path):
    checks = {c.name: c for c in doctor.check_images({}, tmp_path)}
    assert checks["mock-services"].status == "fail"
    assert checks["router"].status == "warn"


def test_containers_running_an_outdated_image(fake_docker):
    fake_docker["inspect mock-services"] = _proc("sha256:old\n")
    fake_docker["inspect agent-blue"] = _proc("sha256:old\n")
    fake_docker["image inspect"] = _proc("sha256:new\n")
    checks = {c.name: c for c in doctor.check_container_images({})}
    assert checks["mock-services image"].status == "fail"
    assert checks["mock-services image"].fix == "docker compose up -d --force-recreate mock-services"
    assert checks["agent-blue image"].status == "warn"


def test_unreadable_deploy_state_fails(tmp_path):
    (tmp_path / "deploy" / "state").mkdir(parents=True)
    (tmp_path / "deploy" / "state" / "state.json").write_text("{torn", encoding="utf-8")
    assert doctor.check_state(tmp_path).status == "fail"


def test_the_doctor_runs_on_the_standard_library_alone():
    """It has to be able to say that the dependencies are missing."""
    probe = ("import importlib.util, sys; spec = importlib.util.spec_from_file_location('d', sys.argv[1]); "
             "m = importlib.util.module_from_spec(spec); sys.modules['d'] = m; spec.loader.exec_module(m); "
             "print([n for n in ('yaml', 'typer', 'rich', 'dotenv', 'jsonschema', 'openai') if n in sys.modules])")
    out = subprocess.run([sys.executable, "-I", "-c", probe, str(ROOT / "scripts" / "doctor.py")],
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "[]"


def test_json_output_and_exit_code(monkeypatch, capsys):
    monkeypatch.setattr(doctor, "run_checks", lambda probe, online: [
        doctor.Check("host", "python", "ok", "3.11"), doctor.Check("stack", "net", "fail", "missing", "fix it")])
    assert doctor.main(["--json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["ok"] is False and data["checks"][1]["fix"] == "fix it"


def test_unknown_flags_are_refused(capsys):
    assert doctor.main(["--prob"]) == 2


def test_a_gateway_failure_quotes_nginxs_own_reason(fake_docker):
    """The 502 seen right after Docker Desktop started was DNS, not configuration."""
    log = ("127.0.0.1 - - [14/Oct/2026:08:59:53 +0000] \"GET /healthz HTTP/1.1\" 200 3\n"
           "2026/10/14 08:59:47 [error] 43#43: *6 api.groq.com could not be resolved (3: Host not found), "
           "client: 172.19.0.7, server: , request: \"GET /openai/v1/models HTTP/1.1\"\n")
    fake_docker["logs"] = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=log)
    fake_docker["inspect mock-services"] = _proc("sha256:mock\n")
    fake_docker["run"] = _proc("502\n")
    check = doctor.check_gateway_online({})
    assert check.status == "fail"
    assert check.detail.endswith("llm-proxy logged: api.groq.com could not be resolved (3: Host not found)")
    assert "proxy (" not in check.fix   # no guessing at causes the log does not show


def test_a_working_gateway(fake_docker):
    fake_docker["inspect mock-services"] = _proc("sha256:mock\n")
    fake_docker["run"] = _proc("200\n")
    assert doctor.check_gateway_online({}).status == "ok"
