"""
Sandbox harness (sandbox/run_test.py).

What the harness owns, it must not take from the agent under test: the world it
acts in, the build that ran, the audit log and its own identity fields. And the
bundled agent must still receive exactly what it always has. No test here starts
a container: every `docker` call goes through a recording fake.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
from typer.testing import CliRunner

import contract
import run_test
from conftest import ROOT, case, transcript

IMAGE_ID = "sha256:" + "a" * 64
OTHER_ID = "sha256:" + "b" * 64
MOCK_IMAGE_ID = "sha256:" + "c" * 64
GRADING = set(contract.GRADING_FIELDS)


def _proc(stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _host_digest(variant: str) -> str:
    return hashlib.sha256((ROOT / "agent" / "variants" / f"{variant}.txt").read_bytes()).hexdigest()


class FakeDocker:
    """Answers the docker commands run_test issues, and records every call in order."""

    def __init__(self, agent_stdout: Optional[str] = None, agent_rc: int = 0, agent_stderr: str = "",
                 images: Optional[Dict[str, str]] = None, init: Optional[Any] = None,
                 audit: Optional[List[Dict[str, Any]]] = None, agent_raises: Optional[BaseException] = None,
                 variant_digest: Optional[str] = None):
        self.agent_stdout = json.dumps(transcript()) if agent_stdout is None else agent_stdout
        self.agent_rc, self.agent_stderr, self.agent_raises = agent_rc, agent_stderr, agent_raises
        self.images = {"creuset-agent:latest": IMAGE_ID} if images is None else images
        self.init = init  # None: a normal create; else a CompletedProcess to return
        self.audit = [{"ts": 1.0, "action": "file_read", "path": "reports/x.txt"}] if audit is None else audit
        self.variant_digest = variant_digest
        self.calls: List[List[str]] = []
        self.inputs: List[Optional[str]] = []
        self.scenario: Optional[Dict[str, Any]] = None  # what the agent container was given
        self.init_body: Optional[Dict[str, Any]] = None
        self.volumes: Dict[str, str] = {}

    def __call__(self, args, timeout=60, input=None):
        args = list(args)
        self.calls.append(args)
        self.inputs.append(input)
        if args[:2] == ["image", "inspect"]:
            ref = args[-1]
            return _proc(self.images[ref] + "\n") if ref in self.images else _proc(
                returncode=1, stderr=f"Error: No such image: {ref}")
        if args[0] == "inspect" and "{{.Image}}" in args:
            return _proc(MOCK_IMAGE_ID + "\n")
        if args[0] == "exec" and "-i" in args:  # world init
            self.init_body = json.loads(input)
            if self.init is not None:
                return self.init
            run_id = args[-1].rsplit("/runs/", 1)[1].split("/")[0]
            return _proc(json.dumps({"run": run_id, "fixtures": self.init_body["fixtures"], "created": True}))
        if args[0] == "exec":  # audit fetch
            return _proc(json.dumps({"run": "x", "entries": self.audit, "fixtures": ["f"]}))
        if args[:2] == ["volume", "create"]:
            self.volumes[args[-1]] = ""
            return _proc(args[-1])
        if args[0] == "volume":
            return _proc()
        if args[0] == "rm":
            return _proc("\n".join(args[2:]))
        if args[0] == "run" and "--entrypoint" in args and "python" in args:
            if run_test._VARIANT_DIGEST in args:
                return _proc(self.variant_digest or _host_digest(args[-1]))
            if run_test._VOLUME_FILL in args:
                mount = args[args.index("-v") + 1]
                self.volumes[mount.split(":")[0]] = input
                return _proc()
            return _proc(json.dumps({"llm_proxy_health": 200, "llm_proxy_other_path": 403,
                                     "mock_services_health": 200, "internet_tcp_1_1_1_1": "OSError",
                                     "internet_dns_example_com": "gaierror"}))
        if args[0] == "run":  # the agent
            mount = args[args.index("-v") + 1]
            source = mount.rsplit(":", 2)[0]  # "C:/..." on Windows has a colon of its own
            raw = self.volumes.get(source) if source in self.volumes else Path(source).read_text(encoding="utf-8")
            self.scenario = json.loads(raw)
            if self.agent_raises is not None:
                raise self.agent_raises
            return _proc(self.agent_stdout, self.agent_rc, self.agent_stderr)
        raise AssertionError(f"unexpected docker call: {args}")

    # ── what happened ──
    def agent_run(self) -> List[str]:
        runs = [c for c in self.calls if c[0] == "run" and "--entrypoint" not in c]
        assert len(runs) == 1, runs
        return runs[0]

    def kinds(self) -> List[str]:
        out = []
        for c in self.calls:
            if c[0] == "exec":
                out.append("init" if "-i" in c else "audit")
            elif c[0] == "run":
                out.append("fill" if run_test._VOLUME_FILL in c else "agent")
            else:
                out.append(" ".join(c[:2]))
        return out


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    """Known settings, no cached image IDs, no developer .env leaking in."""
    for name in ("AGENT_IMAGE", "AGENT_IMAGE_TAG", "CREUSET_SCENARIO_TRANSPORT", "AGENT_API_BASE",
                 "AGENT_MAX_TOKENS", "FINALIZER_MAX_TOKENS", "MAX_LLM_CALLS", "LLM_MAX_RETRIES",
                 "LLM_TIMEOUT_SECONDS", "CREUSET_CANARY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AGENT_MODEL", "test/model")
    run_test._image_ids.clear()
    run_test._variant_checks.clear()
    yield
    run_test._image_ids.clear()
    run_test._variant_checks.clear()


@pytest.fixture
def docker(monkeypatch):
    fake = FakeDocker()
    monkeypatch.setattr(run_test, "_docker", fake)
    return fake


def _use(monkeypatch, fake: FakeDocker) -> FakeDocker:
    monkeypatch.setattr(run_test, "_docker", fake)
    return fake


def _env(cmd: List[str]) -> Dict[str, str]:
    return dict(cmd[i + 1].split("=", 1) for i, a in enumerate(cmd) if a == "-e")


def _labels(cmd: List[str]) -> Dict[str, str]:
    return dict(cmd[i + 1].split("=", 1) for i, a in enumerate(cmd) if a == "--label")


# ── Variants ──────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("variant", ["naive", "hardened", "broken"])
def test_shipped_variants_are_valid(variant, docker):
    assert run_test.validate_variant(variant) is None


@pytest.mark.parametrize("variant", ["../../etc/passwd", "x/y", "", "made-up"])
def test_bad_variants_rejected(variant, docker):
    assert run_test.validate_variant(variant) is not None


def test_stale_image_is_refused_with_the_rebuild_command(monkeypatch):
    """An edited host prompt the image does not carry would be measured as the OLD prompt."""
    fake = _use(monkeypatch, FakeDocker(variant_digest="0" * 64))
    problem = run_test.validate_variant("broken")
    assert problem and "docker compose build agent-blue" in problem and "OLD prompt" in problem
    check = [c for c in fake.calls if run_test._VARIANT_DIGEST in c][0]
    assert IMAGE_ID in check and "--network" in check and check[check.index("--network") + 1] == "none"


def test_variant_missing_from_image_is_refused(monkeypatch):
    _use(monkeypatch, FakeDocker(variant_digest="missing"))
    problem = run_test.validate_variant("hardened")
    assert "not in image" in problem and "docker compose build agent-blue" in problem


def test_unreadable_image_variant_fails_closed(monkeypatch):
    fake = FakeDocker()

    def broken(args, timeout=60, input=None):
        if run_test._VARIANT_DIGEST in args:
            return _proc(returncode=125, stderr="docker: Error response from daemon: boom")
        return fake(args, timeout, input)
    monkeypatch.setattr(run_test, "_docker", broken)
    assert "boom" in run_test.validate_variant("naive")


def test_variant_check_runs_once_per_process(docker):
    assert run_test.validate_variant("naive") is None
    assert run_test.validate_variant("naive") is None
    assert sum(run_test._VARIANT_DIGEST in c for c in docker.calls) == 1
    assert sum(c[:2] == ["image", "inspect"] for c in docker.calls) == 1


def test_variant_check_compares_raw_bytes(docker, tmp_path, monkeypatch):
    """CRLF in, CRLF in the image: the same build. The host digest is of the raw file."""
    (tmp_path / "crlf.txt").write_bytes(b"line one\r\nline two\r\n")
    monkeypatch.setattr(run_test, "_VARIANTS_DIR", tmp_path)
    docker.variant_digest = hashlib.sha256(b"line one\r\nline two\r\n").hexdigest()
    assert run_test.validate_variant("crlf") is None
    run_test._variant_checks.clear()
    docker.variant_digest = hashlib.sha256(b"line one\nline two\n").hexdigest()
    assert run_test.validate_variant("crlf") is not None


def test_no_docker_skips_the_image_check(monkeypatch):
    """preflight reports a missing daemon; validate_variant must not hang on it or crash."""
    def no_docker(args, timeout=60, input=None):
        raise FileNotFoundError("docker")
    monkeypatch.setattr(run_test, "_docker", no_docker)
    assert run_test.validate_variant("hardened") is None
    assert run_test.validate_variant("made-up") is not None  # the host checks still apply


def test_custom_image_variant_is_opaque(monkeypatch):
    fake = _use(monkeypatch, FakeDocker(images={"creuset-agent:latest": IMAGE_ID, "acme/agent:1": OTHER_ID}))
    assert run_test.validate_variant("prod-eu", image="acme/agent:1") is None  # no agent/variants/prod-eu.txt
    assert run_test.validate_variant("../x", image="acme/agent:1") is not None
    assert not any(run_test._VARIANT_DIGEST in c for c in fake.calls)


def test_bundled_image_by_any_name_is_checked(monkeypatch):
    _use(monkeypatch, FakeDocker(images={"creuset-agent:latest": IMAGE_ID, IMAGE_ID: IMAGE_ID}))
    assert run_test.is_bundled_image(IMAGE_ID)
    assert not run_test.is_bundled_image(OTHER_ID)
    assert run_test.validate_variant("made-up", image=IMAGE_ID) is not None


def test_agent_image_tag_names_the_bundled_build(monkeypatch):
    monkeypatch.setenv("AGENT_IMAGE_TAG", "creuset-agent:dev")
    _use(monkeypatch, FakeDocker(images={"creuset-agent:dev": IMAGE_ID}))
    assert run_test.default_image() == "creuset-agent:dev"
    assert run_test.validate_variant("made-up") is not None
    monkeypatch.setenv("AGENT_IMAGE", "acme/agent:1")  # AGENT_IMAGE wins; AGENT_IMAGE_TAG is the alias
    assert run_test.default_image() == "acme/agent:1"


# ── Image resolution ──────────────────────────────────────────────────────────

def test_image_is_resolved_once_and_cases_run_by_id(docker):
    first = run_test.run_case(case(id="PI-001"), "hardened")
    second = run_test.run_case(case(id="PI-002"), "hardened")
    assert sum(c[:2] == ["image", "inspect"] for c in docker.calls) == 1
    agent_runs = [c for c in docker.calls if c[0] == "run"]
    assert all(IMAGE_ID in c and "creuset-agent:latest" not in c for c in agent_runs)
    for t in (first, second):
        assert (t["agent_image"], t["agent_image_id"]) == ("creuset-agent:latest", IMAGE_ID)


def test_missing_image_has_a_plain_message(monkeypatch):
    _use(monkeypatch, FakeDocker(images={}))
    with pytest.raises(RuntimeError, match="docker compose build agent-blue"):
        run_test.resolve_image()
    with pytest.raises(RuntimeError, match="docker pull acme/agent:1"):
        run_test.resolve_image("acme/agent:1")


def test_image_reference_cannot_be_a_flag(docker):
    with pytest.raises(RuntimeError, match="Invalid"):
        run_test.resolve_image("--privileged")
    assert docker.calls == []


def test_missing_image_fails_the_case_before_anything_runs(monkeypatch):
    fake = _use(monkeypatch, FakeDocker(images={}))
    t = run_test.run_case(case(), "hardened")
    assert t["status"] == "container_error" and "not found" in t["error"]
    assert fake.kinds() == ["image inspect"]
    assert t["harness_config"]["AGENT_MAX_TOKENS"] == "700"  # recorded on failures too


# ── The container ─────────────────────────────────────────────────────────────

def test_bundled_bind_command_tail_is_unchanged(docker):
    run_test.run_case(case(), "broken")
    cmd = docker.agent_run()
    assert cmd[-5:] == [IMAGE_ID, "--scenario-file", "/scenario.json", "--variant", "broken"]
    assert cmd[cmd.index("-v") + 1].endswith(":/scenario.json:ro")


def test_sandbox_flags_and_labels(docker):
    t = run_test.run_case(case(), "broken", batch_id="20261014-1_broken_attack_library")
    cmd = docker.agent_run()
    for flag in (["--network", "creuset-net"], ["--cap-drop", "ALL"], ["--pids-limit", "256"],
                 ["--security-opt", "no-new-privileges"]):
        i = cmd.index(flag[0])
        assert cmd[i:i + 2] == flag
    assert "--read-only" in cmd and "--rm" in cmd
    assert _labels(cmd) == {"creuset.project": "creuset", "creuset.run": t["run_id"],
                            "creuset.batch": "20261014-1_broken_attack_library"}
    assert cmd[cmd.index("--name") + 1] == f"creuset-test-{t['run_id']}".lower()


def test_no_batch_label_without_a_batch(docker):
    run_test.run_case(case(), "naive")
    assert "creuset.batch" not in _labels(docker.agent_run())


def test_container_env(docker, monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "gsk_real_secret")
    t = run_test.run_case(case(), "hardened")
    cmd = docker.agent_run()
    env = _env(cmd)
    assert env["OPENAI_BASE_URL"] == env["OPENAI_API_BASE"] == "http://llm-proxy:11434/openai/v1"
    assert env["CREUSET_TOOLS_URL"] == f"http://mock-services:8001/r/{t['run_id']}"
    assert env["CREUSET_RUN_ID"] == t["run_id"]
    assert env["OPENAI_API_KEY"] == "sandbox-placeholder-key"
    assert env["AGENT_MODEL"] == "test/model"
    # Defaults identical to before (and to docker-compose.yml x-agent-env).
    assert {k: env[k] for k in ("MAX_LLM_CALLS", "LLM_MAX_RETRIES", "AGENT_MAX_TOKENS",
                                "FINALIZER_MAX_TOKENS", "LLM_TIMEOUT_SECONDS")} == {
        "MAX_LLM_CALLS": "15", "LLM_MAX_RETRIES": "8", "AGENT_MAX_TOKENS": "700",
        "FINALIZER_MAX_TOKENS": "1024", "LLM_TIMEOUT_SECONDS": "90"}
    assert not any("gsk_real_secret" in a for a in cmd)


def test_effective_settings_are_recorded(docker, monkeypatch):
    monkeypatch.setenv("AGENT_MAX_TOKENS", "400")
    t = run_test.run_case(case(), "hardened")
    assert t["harness_config"] == {"AGENT_MAX_TOKENS": "400", "FINALIZER_MAX_TOKENS": "1024", "MAX_LLM_CALLS": "15"}
    assert t["harness_config"]["AGENT_MAX_TOKENS"] == _env(docker.agent_run())["AGENT_MAX_TOKENS"]


def test_agent_sees_no_grading_field(docker):
    full = case(id="PI-006", input_payload="Summarise reports/q3_close.txt", fixtures=["pipeline_maintenance"],
                required_tools=["read_file"], probe="judge", max_llm_calls=7, tags=["smoke"],
                metadata={"owner": "x"}, mock_responses={"lookup": {"ok": True}})
    run_test.run_case(full, "broken")
    assert docker.scenario == contract.agent_scenario(full)
    assert not GRADING & set(docker.scenario)
    assert "mock_responses" not in docker.scenario  # the harness's to set up, not the agent's to read
    assert docker.scenario["fixtures"] == ["pipeline_maintenance"] and docker.scenario["max_llm_calls"] == 7


def test_world_is_initialised_before_the_agent_runs(docker):
    run_test.run_case(case(fixtures=["poisoned_db_record"], mock_responses={"lookup": {"id": 1}}), "naive")
    assert docker.kinds() == ["image inspect", "init", "agent", "audit"]
    assert docker.init_body == {"fixtures": ["poisoned_db_record"], "responses": {"lookup": {"id": 1}}}
    init = [c for c in docker.calls if c[0] == "exec" and "-i" in c][0]
    assert init[:4] == ["exec", "-i", "mock-services", "python"]  # the image's own Python, not curl


def test_init_without_canned_responses_sends_fixtures_only(docker):
    run_test.run_case(case(), "naive")
    assert docker.init_body == {"fixtures": []}


@pytest.mark.parametrize("reply", [
    _proc(returncode=3, stderr="HTTP 409: Run x already exists with fixtures []"),
    _proc(returncode=1, stderr="Traceback (most recent call last):\n  ...\nConnectionRefusedError: refused"),
    _proc("not json"),
])
def test_world_init_failure_is_container_error_and_nothing_runs(monkeypatch, reply):
    fake = _use(monkeypatch, FakeDocker(init=reply))
    t = run_test.run_case(case(), "naive")
    assert t["status"] == "container_error" and t["error"].startswith("World init failed")
    assert "agent" not in fake.kinds()
    if reply.returncode == 1:
        assert "ConnectionRefusedError" in t["error"]  # the last line, not "Traceback"


def test_preexisting_world_is_refused(monkeypatch):
    fake = FakeDocker()
    _use(monkeypatch, fake)

    def reply_for(args, timeout=60, input=None):
        if args[0] == "exec" and "-i" in args:
            run_id = args[-1].rsplit("/runs/", 1)[1].split("/")[0]
            return _proc(json.dumps({"run": run_id, "fixtures": [], "created": False}))
        return fake(args, timeout, input)
    monkeypatch.setattr(run_test, "_docker", reply_for)
    t = run_test.run_case(case(), "naive")
    assert t["status"] == "container_error" and "already existed" in t["error"]


def test_timeout_removes_the_container(monkeypatch):
    fake = _use(monkeypatch, FakeDocker(agent_raises=subprocess.TimeoutExpired("docker", 180)))
    t = run_test.run_case(case(), "naive")
    assert t["status"] == "timeout"
    assert ["rm", "-f", f"creuset-test-{t['run_id']}".lower()] in fake.calls


def test_unexpected_error_is_a_harness_error(monkeypatch):
    _use(monkeypatch, FakeDocker(agent_raises=ValueError("surprise")))
    t = run_test.run_case(case(), "naive")
    assert t["status"] == "harness_error" and "surprise" in t["error"]
    assert t["agent_image_id"] == IMAGE_ID and t["audit_source"] == "harness"


def test_bad_variant_never_reaches_docker(docker):
    t = run_test.run_case(case(), "../../x")
    assert t["status"] == "harness_error" and docker.calls == []


# ── Volume transport ──────────────────────────────────────────────────────────

def test_volume_transport(docker, monkeypatch):
    monkeypatch.setenv("CREUSET_SCENARIO_TRANSPORT", "volume")
    full = case(fixtures=["cleanup_notice"], input_payload="Read the notice.")
    t = run_test.run_case(full, "hardened", batch_id="b-1")
    volume = f"creuset-in-{t['run_id']}".lower()
    assert t["status"] == "completed"
    assert docker.kinds() == ["image inspect", "init", "inspect --format", "volume create", "fill", "agent",
                              "volume rm", "audit"]
    fill = [c for c in docker.calls if run_test._VOLUME_FILL in c][0]
    assert "-i" in fill and f"{volume}:/creuset-in" in fill and MOCK_IMAGE_ID in fill
    assert fill[fill.index("--network") + 1] == "none"
    assert json.loads(docker.inputs[docker.calls.index(fill)]) == contract.agent_scenario(full)
    create = [c for c in docker.calls if c[:2] == ["volume", "create"]][0]
    assert _labels(create)["creuset.batch"] == "b-1"
    cmd = docker.agent_run()
    assert cmd[cmd.index("-v") + 1] == f"{volume}:/creuset-in:ro"
    assert cmd[-5:] == [IMAGE_ID, "--scenario-file", "/creuset-in/scenario.json", "--variant", "hardened"]
    assert docker.scenario == contract.agent_scenario(full)
    assert ["volume", "rm", "-f", volume] in docker.calls


def test_volume_is_removed_after_a_timeout(monkeypatch):
    monkeypatch.setenv("CREUSET_SCENARIO_TRANSPORT", "volume")
    fake = _use(monkeypatch, FakeDocker(agent_raises=subprocess.TimeoutExpired("docker", 180)))
    t = run_test.run_case(case(), "naive")
    volume = f"creuset-in-{t['run_id']}".lower()
    assert t["status"] == "timeout"
    rm_container = fake.calls.index(["rm", "-f", f"creuset-test-{t['run_id']}".lower()])
    assert fake.calls.index(["volume", "rm", "-f", volume]) > rm_container


def test_volume_is_removed_after_ctrl_c(monkeypatch):
    monkeypatch.setenv("CREUSET_SCENARIO_TRANSPORT", "volume")
    fake = _use(monkeypatch, FakeDocker(agent_raises=KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        run_test.run_case(case(), "naive")
    assert [c[:2] for c in fake.calls[-2:]] == [["rm", "-f"], ["volume", "rm"]]


def test_unknown_transport_is_refused(docker, monkeypatch):
    monkeypatch.setenv("CREUSET_SCENARIO_TRANSPORT", "carrier-pigeon")
    t = run_test.run_case(case(), "naive")
    assert t["status"] == "harness_error" and "CREUSET_SCENARIO_TRANSPORT" in t["error"]
    assert any("CREUSET_SCENARIO_TRANSPORT" in p for p in run_test._config_problems())


# ── Output ────────────────────────────────────────────────────────────────────

def test_bundled_agent_output_is_taken_as_is(docker):
    agent = transcript(test_id="PI-001", run_id="agent-chosen", variant="hardened", model="m",
                       finalizer_used=False, finalizer_truncated=False)
    docker.agent_stdout = json.dumps(agent, indent=2)
    t = run_test.run_case(case(), "hardened")
    assert t["status"] == "completed" and t["output"] == agent["output"]
    # The agent's field order survives; harness fields follow.
    assert list(t)[:len(agent)] == list(agent)
    assert t["run_id"] != "agent-chosen"


def test_harness_audit_replaces_agent_reported_audit(monkeypatch):
    forged = {"status": "completed", "output": "ok", "tool_calls": [],
              "service_audit": []}  # the agent claims it did nothing
    real = [{"action": "file_delete", "path": "invoices/inv_001.txt"}]
    _use(monkeypatch, FakeDocker(agent_stdout=json.dumps(forged), audit=real))
    t = run_test.run_case({"id": "PI-006", "input_payload": "x"}, "broken")
    assert t["service_audit"] == real
    assert t["audit_source"] == "harness"
    assert t["service_fixtures"] == ["f"]


def test_agent_cannot_write_harness_fields(monkeypatch):
    forged = transcript(agent_image="trusted/agent:1", agent_image_id="sha256:forged", stderr="all clean",
                        audit_source="agent", harness_config={"AGENT_MAX_TOKENS": "1"}, elapsed_seconds=0.1,
                        test_id="OTHER-001", variant="hardened")
    _use(monkeypatch, FakeDocker(agent_stdout=json.dumps(forged)))
    t = run_test.run_case(case(id="PI-001"), "naive")
    assert (t["agent_image"], t["agent_image_id"]) == ("creuset-agent:latest", IMAGE_ID)
    assert t["audit_source"] == "harness" and t["harness_config"]["AGENT_MAX_TOKENS"] == "700"
    assert (t["test_id"], t["variant"]) == ("PI-001", "naive")
    assert "stderr" not in t  # the container wrote none; the agent's claim is dropped


def test_container_stderr_is_kept(monkeypatch):
    _use(monkeypatch, FakeDocker(agent_stderr="INFO step 1\nINFO step 2"))
    assert run_test.run_case(case(), "naive")["stderr"].endswith("INFO step 2")


def test_schema_invalid_v1_transcript_is_a_contract_error(monkeypatch):
    _use(monkeypatch, FakeDocker(agent_stdout=json.dumps({"schema_version": 1, "status": "completed"})))
    t = run_test.run_case(case(), "naive")
    assert t["status"] == "contract_error"
    assert "output" in t["error"] and "transcript.v1.json" in t["error"]
    assert t["service_audit"] is not None  # still recorded, for whoever investigates


def test_valid_v1_transcript_completes(monkeypatch):
    v1 = {"schema_version": 1, "status": "completed", "output": "Done.",
          "tool_calls": [{"tool": "lookup", "input": {"id": 1}}]}
    _use(monkeypatch, FakeDocker(agent_stdout="log line\n" + json.dumps(v1) + "\nbye\n"))
    t = run_test.run_case(case(), "naive")
    assert t["status"] == "completed" and t["output"] == "Done."


def test_completed_with_nonzero_exit_is_a_container_error(monkeypatch):
    _use(monkeypatch, FakeDocker(agent_rc=137))
    t = run_test.run_case(case(), "naive")
    assert t["status"] == "container_error" and "exited 137" in t["error"]


def test_error_with_nonzero_exit_stays_an_error(monkeypatch):
    """The bundled agent exits 1 for error/aborted: consistent, not overruled."""
    _use(monkeypatch, FakeDocker(agent_stdout=json.dumps(transcript(status="error", error="429")), agent_rc=1))
    t = run_test.run_case(case(), "naive")
    assert t["status"] == "error" and t["error"] == "429"


@pytest.mark.parametrize("rc,status", [(0, "parse_error"), (2, "container_error")])
def test_no_transcript(monkeypatch, rc, status):
    _use(monkeypatch, FakeDocker(agent_stdout="Traceback: nothing useful", agent_rc=rc, agent_stderr="boom"))
    t = run_test.run_case(case(), "naive")
    assert t["status"] == status
    assert "stdout" in t["error"] and "boom" in t["error"]  # tells the author the contract
    assert t["agent_image_id"] == IMAGE_ID and t["harness_config"] is not None


# ── Config and preflight ──────────────────────────────────────────────────────

def test_agent_model_unset_is_a_problem_not_a_default(docker, monkeypatch):
    monkeypatch.delenv("AGENT_MODEL")
    t = run_test.run_case(case(), "naive")
    assert t["status"] == "harness_error" and "AGENT_MODEL" in t["error"]
    assert docker.calls == []
    # Reported even beside a Docker problem, so one run of --check lists both.
    monkeypatch.setattr(run_test, "_docker", lambda *a, **k: _proc(returncode=1, stderr="daemon down"))
    problems = run_test.preflight()
    assert len(problems) == 2 and "AGENT_MODEL" in problems[0] and "daemon down" in problems[1]


def test_agent_max_tokens_unset_is_a_warning(monkeypatch):
    assert any("AGENT_MAX_TOKENS" in w for w in run_test.preflight_warnings())
    monkeypatch.setenv("AGENT_MAX_TOKENS", "400")
    assert run_test.preflight_warnings() == []


def test_preflight_shows_dockers_own_error(monkeypatch):
    def down(args, timeout=60, input=None):
        return _proc(returncode=1, stderr="WARNING: something\nCannot connect to the Docker daemon at "
                                          "unix:///var/run/docker.sock. Is the docker daemon running?\n")
    monkeypatch.setattr(run_test, "_docker", down)
    problems = run_test.preflight()
    assert len(problems) == 1 and "Cannot connect to the Docker daemon at unix:///var/run/docker.sock" in problems[0]


def test_preflight_ready(monkeypatch):
    fake = FakeDocker()

    def ready(args, timeout=60, input=None):
        if args[0] == "info":
            return _proc("27.0.1")
        if args[:2] == ["network", "inspect"]:
            return _proc("true")
        if args[0] == "inspect":
            return _proc("running healthy")
        return fake(args, timeout, input)
    monkeypatch.setattr(run_test, "_docker", ready)
    assert run_test.preflight() == []
    assert run_test.preflight("acme/agent:1") == ["Agent image 'acme/agent:1' not found on the Docker daemon "
                                                  "(Error: No such image: acme/agent:1). Build or pull it "
                                                  "first (docker pull acme/agent:1)."]


def test_names_come_from_the_environment():
    code = ("import sys; sys.path.insert(0, sys.argv[1]); import run_test as r; "
            "print(r.NETWORK, r.MOCK_CONTAINER, r.PROXY_CONTAINER, r.PROJECT, r.INFRA_CONTAINERS, "
            "r._SANDBOX_FLAGS[1], r._container_env('x')['CREUSET_TOOLS_URL'], "
            "r._container_env('x')['OPENAI_API_BASE'])")
    env = {k: v for k, v in os.environ.items() if not k.startswith("CREUSET_")}
    # AGENT_API_BASE empty, not absent: a developer's .env sets it, and load_dotenv
    # never overrides a variable that exists. Empty means unset to the harness.
    env.update(CREUSET_NETWORK="acme-net", CREUSET_MOCK_CONTAINER="acme-mock",
               CREUSET_PROXY_CONTAINER="acme-proxy", CREUSET_PROJECT="acme", AGENT_API_BASE="")
    out = subprocess.run([sys.executable, "-c", code, str(ROOT / "sandbox")], env=env,
                         capture_output=True, text=True, timeout=60, check=True).stdout.split()
    assert out == ["acme-net", "acme-mock", "acme-proxy", "acme", "('acme-proxy',", "'acme-mock')",
                   "acme-net", "http://acme-mock:8001/r/x", "http://acme-proxy:11434/openai/v1"]


def test_isolation_probe_runs_in_the_mock_services_image(docker):
    result = run_test.isolation_probe()
    assert result["ok"] is True
    probe = [c for c in docker.calls if run_test._PROBE in c][0]
    assert MOCK_IMAGE_ID in probe and probe[-2:] == ["llm-proxy", "mock-services"]
    assert probe[probe.index("--network") + 1] == "creuset-net"


# ── Audit ─────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("proc", [_proc(returncode=22), _proc("not json"), _proc('{"entries": "x"}')])
def test_unavailable_audit_is_none(monkeypatch, proc):
    monkeypatch.setattr(run_test, "_docker", lambda *a, **k: proc)
    assert run_test.fetch_audit("run-1") is None


def test_run_id_is_url_quoted(monkeypatch):
    seen = {}

    def fake(args, timeout=60, input=None):
        seen["url"] = args[-1]
        return _proc('{"entries": []}')
    monkeypatch.setattr(run_test, "_docker", fake)
    run_test.fetch_audit("a&run=b c")
    assert seen["url"].endswith("run=a%26run%3Db%20c")


# ── Cleanup ───────────────────────────────────────────────────────────────────

def test_remove_batch_containers(monkeypatch):
    calls = []

    def fake(args, timeout=60, input=None):
        calls.append(args)
        if args[0] == "ps":
            return _proc("c1\nc2\n")
        if args[0] == "rm":
            return _proc("c1\nc2\n")
        if args[:2] == ["volume", "ls"]:
            return _proc("creuset-in-x\n")
        return _proc()
    monkeypatch.setattr(run_test, "_docker", fake)
    assert run_test.remove_batch_containers("b-1") == 2
    assert calls[0] == ["ps", "-aq", "--filter", "label=creuset.batch=b-1"]
    assert calls[1] == ["rm", "-f", "c1", "c2"]
    assert calls[-1] == ["volume", "rm", "-f", "creuset-in-x"]


@pytest.mark.parametrize("batch", ["", "  ", "a\nb"])
def test_remove_batch_containers_refuses_a_blank_batch(docker, batch):
    assert run_test.remove_batch_containers(batch) == 0
    assert docker.calls == []


def test_cleanup_cli(monkeypatch):
    calls = []

    def fake(args, timeout=60, input=None):
        calls.append(args)
        return _proc("c1\n" if args[0] in ("ps", "rm") else "")
    monkeypatch.setattr(run_test, "_docker", fake)
    result = CliRunner().invoke(run_test.app, ["--cleanup", "all"])
    assert result.exit_code == 0
    assert calls[0] == ["ps", "-aq", "--filter", "label=creuset.project=creuset", "--filter", "label=creuset.run"]
    calls.clear()
    assert CliRunner().invoke(run_test.app, ["--cleanup", "b-7"]).exit_code == 0
    assert calls[0][-1] == "label=creuset.batch=b-7"


# ── Cases and files ───────────────────────────────────────────────────────────

def test_find_case_in_a_named_library(tmp_path):
    lib = tmp_path / "acme.yaml"
    lib.write_text("library: {schema_version: 1, kind: benign}\ncases:\n  - id: ACME-001\n    input_payload: hi\n",
                   encoding="utf-8")
    assert run_test.find_case("ACME-001", lib)["input_payload"] == "hi"
    with pytest.raises(ValueError, match="acme.yaml"):
        run_test.find_case("PI-001", lib)
    assert run_test.find_case("PI-006")["id"] == "PI-006"  # bundled libraries by default


def test_saved_transcript_stays_in_its_directory(tmp_path):
    path = run_test.save_transcript({"test_id": "../../evil", "variant": "x/y"}, tmp_path)
    assert path.parent == tmp_path


def test_canary_warning(tmp_path, monkeypatch, docker):
    assert run_test.canary_warning("hardened") is None  # the shipped prompts carry it
    (tmp_path / "mine.txt").write_text("You are helpful.", encoding="utf-8")
    monkeypatch.setattr(run_test, "_VARIANTS_DIR", tmp_path)
    assert "canary" in run_test.canary_warning("mine")
    monkeypatch.setenv("CREUSET_CANARY", "")  # deliberately none: the rule layer skips the check
    assert run_test.canary_warning("mine") is None
