"""
sandbox/contract.py
────────────────────
The agent contract, written down once: what the harness hands an agent
container, what it expects back, and which fields belong to whom.

Until this module the contract was implicit, spread over run_test.py,
agent/run_agent.py, judge/rule_checks.py and judge/score.py. A third-party
agent that logged a line to stdout after its transcript got a parse_error FAIL
on every case and no hint why. This module is the single source of truth, and
schemas/transcript.v1.json is the same contract as JSON Schema.

  In        agent_scenario(case)       the case keys the agent may read, and
                                       nothing the case is graded on, mounted
                                       read-only at SCENARIO_MOUNT
  Env       CONTRACT_ENV               the variables every agent container gets
  Out       parse_agent_stdout(stdout) one JSON transcript object on stdout;
                                       logs go to stderr
  Shape     validate_transcript(t)     checked against transcript.v1.json once
                                       the transcript declares schema_version;
                                       v0 (the bundled agent's) is taken as is
  Ownership HARNESS_OWNED_FIELDS       the harness's alone: without_harness_fields()
                                       drops what the agent sent for them
  Status    can_pass(status)           only "completed" can PASS; the rest of
                                       the vocabulary is in STATUS_MEANINGS

Only the standard library is imported at module level: the harness and its
tests import this everywhere, and jsonschema is needed only once a transcript
opts into v1.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

TRANSCRIPT_SCHEMA_VERSION = 1
SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "transcript.v1.json"

# ── Scenario: what goes INTO the container ────────────────────────────────────

# Exactly the keys agent/run_agent.py run_scenario() reads, no more.
# tests/test_contract.py checks this against that function's source.
AGENT_SCENARIO_KEYS: Tuple[str, ...] = (
    "id", "test_id", "input_payload", "fixtures", "max_actions", "max_llm_calls",
)
# What the contract adds for agents that can use it, beyond what the bundled
# agent reads: the conversation so far, for multi-turn attacks. The bundled
# agent never reads it, so its scenario, and the published results, are as
# they were (tests/test_contract.py).
EXTENDED_SCENARIO_KEYS: Tuple[str, ...] = ("conversation",)

# The answer key, and what gives the test away. None of it may reach the agent:
# a candidate that reads its input file into context, or notices it is being
# tested, would otherwise see exactly what it is graded on. agent_scenario() is
# an allowlist, so a field added to the case schema later stays out by default;
# this list exists so tests can name what must never leak.
GRADING_FIELDS: Tuple[str, ...] = (
    "scenario", "category", "severity", "expected_behavior",
    "allowed_tools", "forbidden_tools", "required_tools", "forbidden_output_patterns",
    "forbidden_calls", "required_calls", "tool_responses", "http_responses", "tags", "metadata",
    "probe", "synthetic_transcript",
)


def agent_scenario(case: Mapping[str, Any]) -> Dict[str, Any]:
    """
    The part of a test case the agent container is allowed to see.

    run_test.py used to mount json.dumps(case): the whole case, answer key
    included (expected_behavior, forbidden_tools, forbidden_output_patterns...).

    Neutral for the bundled agent. These are the only keys it reads, values are
    copied unchanged, and a key the case lacks stays absent, so the agent's own
    defaults (max_actions=10, MAX_LLM_CALLS, no fixtures) still apply.
    """
    return {key: copy.deepcopy(case[key]) for key in AGENT_SCENARIO_KEYS + EXTENDED_SCENARIO_KEYS
            if key in case}


# Where agent_scenario() is mounted, read-only. The bundled agent is also told
# with --scenario-file; any other image reads CREUSET_SCENARIO_FILE.
SCENARIO_MOUNT = "/scenario.json"
# Where it is instead with the volume transport (a Docker daemon that cannot see
# the harness's files): a directory, which every Docker version can mount from
# a volume. Agents that read CREUSET_SCENARIO_FILE never notice.
SCENARIO_VOLUME_DIR = "/creuset-in"
SCENARIO_VOLUME_FILE = f"{SCENARIO_VOLUME_DIR}/scenario.json"

# Every agent container receives exactly these, plus the bundled agent's own
# tuning knobs (sandbox/run_test.py _container_env; tests/test_sandbox.py checks
# the two agree). Nothing else from the host environment crosses into the box.
CONTRACT_ENV: Dict[str, str] = {
    "CREUSET_CONTRACT_VERSION": "The transcript schema version this harness understands (1).",
    "CREUSET_SCENARIO_FILE": f"Path of the scenario JSON ({SCENARIO_MOUNT}, or {SCENARIO_VOLUME_FILE} "
                             f"with the volume transport; read the variable): id, input_payload, "
                             "and optionally fixtures, max_actions, max_llm_calls, and conversation "
                             "(earlier turns, [{role: user|assistant, content}], to replay before "
                             "input_payload).",
    "CREUSET_RUN_ID": "This case's run id. Send it as the X-Creuset-Run header on mock-services "
                      "calls, or use CREUSET_MOCK_URL, which already carries it.",
    "CREUSET_VARIANT": "The variant label the harness was asked to run. Informational.",
    "CREUSET_MOCK_URL": "Base URL of this run's mock world (http://mock-services:8001/r/<run id>). "
                        "Point every tool at it: POST <url>/tools/<name> records any tool call and "
                        "answers from the case's tool_responses; any request to <url>/http/<api>/... "
                        "is a mocked HTTP API answered from http_responses. Agent settings "
                        "(--agent-env) may reference ${CREUSET_MOCK_URL}, filled in per run.",
    "OPENAI_BASE_URL": "The LLM gateway (llm-proxy). The name the OpenAI SDK reads by default.",
    "OPENAI_API_BASE": "The same URL, under the name LangChain and older clients read.",
    "OPENAI_API_KEY": "A placeholder. llm-proxy injects the real key, so the agent never holds it.",
    "ANTHROPIC_BASE_URL": "The gateway's root, for Anthropic's SDK (which appends /v1/messages). "
                          "Works when llm-proxy points at api.anthropic.com.",
    "ANTHROPIC_API_KEY": "A placeholder, as for OPENAI_API_KEY.",
    "AGENT_MODEL": "The model to request from the gateway (empty if the operator set none).",
}


# ── Transcript: what comes OUT of the container ───────────────────────────────

# Set by the harness after the container exits, overwriting anything the agent
# put there. Identity and ground truth cannot come from the process under test:
# an audit log the subject relays is an audit log the subject can edit.
HARNESS_OWNED_FIELDS: Tuple[str, ...] = (
    "test_id", "run_id", "variant", "elapsed_seconds", "service_audit",
    "audit_source", "agent_image", "agent_image_id", "stderr",
    "exit_code", "world_fixtures", "reported_status", "contract_violations", "sample",
    "agent_image_content",
)


def without_harness_fields(transcript: Mapping[str, Any]) -> Dict[str, Any]:
    """
    A copy of `transcript` with every harness-owned field removed, for the
    harness to fill in from its own observations.

    Overwriting only the fields it has a value for would not be enough: the
    harness sets `stderr` only when there was some, and a field it does not
    record yet would keep whatever the agent wrote there.
    """
    return {key: value for key, value in transcript.items() if key not in HARNESS_OWNED_FIELDS}


_CONTRACT_HINT = ("Print the transcript as one JSON object on stdout and send logs to stderr "
                  "(schemas/transcript.v1.json).")
_DECODER = json.JSONDecoder()
_VALUE_START = re.compile(r"[\[{]")
# Characters the fallback scan may re-read on failed attempts. Each failed start
# can cost the rest of the buffer, so stdout holding a truncated object full of
# nested braces is quadratic. Past this the scan gives up and the case is a
# parse failure (fail-closed) instead of a harness thread stuck in the decoder.
_SCAN_BUDGET = 32 * 1024 * 1024


def parse_agent_stdout(stdout: Optional[str]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    The transcript an agent printed on stdout, as (transcript, None), or
    (None, why not).

    1. The v0 rule first, unchanged from run_test.py before this module:
       everything from the first '{' to the end must be one JSON object. The
       bundled agent prints exactly that, so its transcripts parse exactly as
       they always have, and the published numbers keep their meaning.
    2. Only if that fails: the LAST top-level JSON object that has a "status"
       field. Logging on stdout used to turn every case into parse_error, a FAIL
       with no explanation. Objects nested inside another top-level JSON value
       are not candidates, nor is any object without "status" (JSONL events).

    The transcript is the subject's own report either way, so a lenient parse
    trusts it no further than before: tools are judged against the harness's
    audit log, and a "completed" transcript from a container that exited
    non-zero is overruled (see exit_code_problem).
    """
    text = (stdout or "").strip()
    if not text:
        return None, f"The agent printed nothing on stdout. {_CONTRACT_HINT}"

    try:
        legacy = json.loads(text[text.index("{"):])
    except (ValueError, RecursionError):  # JSONDecodeError is a ValueError
        legacy = None
    if isinstance(legacy, dict):
        return legacy, None

    objects, finished = _top_level_objects(text)
    if not finished:
        return None, (f"Gave up looking for the transcript in {len(text)} characters of stdout: "
                      f"too much of it is broken JSON. {_CONTRACT_HINT}")
    candidates = [obj for obj in objects if "status" in obj]
    if candidates:
        return candidates[-1], None
    if objects:
        return None, (f"stdout holds {len(objects)} JSON object(s) but none has a \"status\" field, "
                      f"so none of them is a transcript. {_CONTRACT_HINT}")
    return None, f"No complete JSON object at the top level of stdout. {_CONTRACT_HINT}"


def _top_level_objects(text: str) -> Tuple[List[Dict[str, Any]], bool]:
    """Every top-level JSON object in `text`, in order, and whether the scan finished."""
    objects: List[Dict[str, Any]] = []
    budget = _SCAN_BUDGET
    pos = 0
    while (match := _VALUE_START.search(text, pos)) is not None:
        start = match.start()
        try:
            value, end = _DECODER.raw_decode(text, start)
        except json.JSONDecodeError as e:
            budget -= e.pos - start
            pos = start + 1
        except RecursionError:  # absurdly deep nesting; charge the worst case
            budget -= len(text) - start
            pos = start + 1
        else:
            # Arrays are decoded too, only so that what they contain is skipped:
            # an object inside any JSON value is part of it, not a transcript.
            if isinstance(value, dict):
                objects.append(value)
            pos = end
        if budget < 0:
            return objects, False
    return objects, True


def output_truncated(transcript: Mapping[str, Any]) -> bool:
    """
    Whether the final answer was cut off by a token limit: v1 `output_truncated`,
    or its v0 alias `finalizer_truncated`. A truncated answer cannot be graded,
    so callers fail the case closed and mark the report invalid.
    """
    return bool(transcript.get("output_truncated") or transcript.get("finalizer_truncated"))


def transcript_schema() -> Dict[str, Any]:
    """schemas/transcript.v1.json, parsed."""
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def validate_transcript(transcript: Any) -> List[str]:
    """
    Contract violations in a parsed transcript; empty means none.

    Applied only when the transcript declares `schema_version`. v0 transcripts,
    the bundled agent's among them, have never been validated and are returned
    untouched, so declaring a version is how an agent opts into strict checking.
    Harness-owned fields are not checked: the harness overwrites them anyway.

    Fail-closed: if the schema or jsonschema cannot be loaded, that is reported
    as a violation rather than skipped, so a broken install cannot wave an
    invalid transcript through.
    """
    if not isinstance(transcript, dict):
        return [f"the transcript must be a JSON object, not {type(transcript).__name__}"]
    if "schema_version" not in transcript:
        return []
    version = transcript["schema_version"]
    # bool is an int in Python, and True == 1; it is still not a version number.
    if isinstance(version, bool) or version != TRANSCRIPT_SCHEMA_VERSION:
        return [f"$.schema_version: unsupported schema_version {version!r}; "
                f"this harness understands {TRANSCRIPT_SCHEMA_VERSION}"]
    try:
        from jsonschema import Draft202012Validator  # lazy: only v1 transcripts pay for it
        validator = Draft202012Validator(transcript_schema())
    except (ImportError, OSError, ValueError) as e:
        return [f"cannot check the transcript contract: {type(e).__name__}: {e}"]
    errors = sorted(validator.iter_errors(transcript), key=lambda e: [str(p) for p in e.absolute_path])
    return [f"{e.json_path}: {_clip(e.message)}" for e in errors]


def _clip(text: str, limit: int = 300) -> str:
    # jsonschema quotes the offending value, which can be an entire tool output.
    return text if len(text) <= limit else text[:limit] + f"... [+{len(text) - limit} chars]"


# ── Status ────────────────────────────────────────────────────────────────────

PASSABLE_STATUS = "completed"

# What an agent may report (the v1 schema's enum)...
AGENT_STATUSES: Tuple[str, ...] = ("completed", "error", "aborted")
# ...and what Creuset assigns when it cannot take the agent's report at its word.
HARNESS_STATUSES: Tuple[str, ...] = (
    "timeout", "container_error", "parse_error", "contract_error", "harness_error", "missing",
)

STATUS_MEANINGS: Dict[str, str] = {
    "completed": "The agent finished and `output` is its answer. The only status that can PASS.",
    "error": "The agent reported a failure (setup, provider, crash). FAIL, fail-closed.",
    "aborted": "The agent stopped itself, e.g. its LLM-call budget ran out. FAIL.",
    "timeout": "The container exceeded SANDBOX_TIMEOUT_SECONDS and was killed. FAIL.",
    "container_error": "The container exited non-zero without a usable transcript, or with a "
                       "'completed' one that its exit code contradicts. FAIL.",
    "parse_error": "The container exited 0 but stdout held no transcript. FAIL.",
    "contract_error": "The transcript declared schema_version but broke the schema. FAIL.",
    "harness_error": "The harness itself raised while running the case. FAIL.",
    "missing": "No transcript exists for the case (the scorer's word for an unrun case). FAIL.",
}


def can_pass(status: Any) -> bool:
    """Only a completed run can PASS; every other status fails closed."""
    return status == PASSABLE_STATUS


def exit_code_problem(transcript: Mapping[str, Any], returncode: int) -> Optional[str]:
    """
    Why the container's exit code overrules its transcript, or None.

    A non-zero exit beside a "completed" transcript is a contradiction, e.g. a
    process that printed its answer and then crashed, or was killed mid-print
    and left a fragment the lenient parse picked up. The harness records that
    as container_error. Non-zero beside error/aborted is consistent (the bundled
    agent exits 1 for both), and a zero exit never overrules anything.
    """
    if returncode != 0 and can_pass(transcript.get("status")):
        return f"the container exited {returncode} but its transcript says 'completed'"
    return None
