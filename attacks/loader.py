"""
attacks/loader.py
─────────────────
Batch runner: validates a test library (attack_library.yaml or
benign_tasks.yaml) and runs its cases through the sandbox, each in its own
fresh container (sandbox/run_test.py).

Usage:
  # Validate only (no containers)
  python attacks/loader.py --dry-run

  # Run all adversarial cases against a variant
  python attacks/loader.py --variant naive

  # Benign tasks (false-positive / over-refusal measurement)
  python attacks/loader.py --library attacks/benign_tasks.yaml --variant hardened

  # A subset
  python attacks/loader.py --variant hardened --category prompt_injection
  python attacks/loader.py --variant hardened --cases PI-001,TM-002
  python attacks/loader.py --library attacks/generic_agent.yaml --tag owasp-llm07 ...

  # Finish a batch the provider's quota cut short (re-runs only what is missing)
  python attacks/loader.py --resume logs/runs/<batch>
  python attacks/loader.py --resume logs/runs/<batch> --redo-empty

  # Your own agent image and library (see sandbox/contract.py, schemas/library.v1.json)
  python attacks/loader.py --library my_cases.yaml --agent-image my-agent:1.4 --variant v1.4

Exit codes: 0 every run made, 1 bad library or nothing selected, 2 refused
before running (bad arguments, sandbox not ready), 3 the batch stopped early
(circuit breaker: the runs it made are kept, finish it with --resume),
130 interrupted.

Output (one folder per batch):
  logs/runs/<timestamp>_<variant>_<library>/
      <ID>.json          one transcript per case
      manifest.json      what ran → consumed by judge/score.py
"""

from __future__ import annotations

import json
import os
import re
import signal
import sys
import threading
import time
import uuid
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

import typer
import yaml
from dotenv import load_dotenv
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table


# Windows consoles/pipes default to cp1252; force UTF-8 so rich output never crashes.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_ROOT / ".env")
sys.path.insert(0, str(_ROOT / "sandbox"))
sys.path.insert(0, str(_ROOT / "judge"))
import call_policy  # noqa: E402
from batch_files import (  # noqa: E402
    LIBRARY_SNAPSHOT, file_sha256, git_source, library_drift, library_path, recorded_library, recorded_name,
)
from run_test import (  # noqa: E402
    Subject, env_fingerprint, image_content, image_id, limits_from_env, make_subject, parse_agent_env,
    preflight, remove_containers, run_case,
)

app = typer.Typer(add_completion=False)
console = Console()

DEFAULT_LIBRARY = _ROOT / "attacks" / "attack_library.yaml"
RUNS_DIR = _ROOT / "logs" / "runs"
LIBRARY_SCHEMA = _ROOT / "schemas" / "library.v1.json"
MANIFEST_VERSION = 1
# The tool inventory of a library that declares none: the bundled agent's tools.
BUNDLED_TOOLS = ["send_email", "delete_file", "charge_payment", "query_database", "read_file", "list_files"]
_TOOLS = BUNDLED_TOOLS  # pre-library-schema name, kept for anything importing it
# Must equal the keys of _FIXTURES in sandbox/mock_services/main.py, which holds
# the content (tests/test_loader.py checks the two agree).
_FIXTURES = ["poisoned_db_record", "poisoned_filename", "base64_metadata", "cleanup_notice",
             "pipeline_maintenance"]
# mock-services' own limit on one canned response; refused here rather than as
# a 400 when the harness creates the world, mid-batch.
_MAX_RESPONSE_BYTES = 64 * 1024

# ── Schema ────────────────────────────────────────────────────────────────────


def _schema() -> Dict[str, Any]:
    return json.loads(LIBRARY_SCHEMA.read_text(encoding="utf-8"))


def load_library_doc(path: Path) -> Any:
    """The library file as parsed: a list of cases, or {"cases": [...], "tools": [...], ...}."""
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def library_cases(raw: Any) -> List[Dict[str, Any]]:
    if isinstance(raw, list):
        return raw
    return (raw or {}).get("cases", []) if isinstance(raw, dict) else []


def library_tools(raw: Any) -> List[str]:
    """The tools a library's cases may name: its declared inventory, else the bundled six."""
    declared = raw.get("tools") if isinstance(raw, dict) else None
    return list(declared) if declared else list(BUNDLED_TOOLS)


def load_library(path: Path) -> List[Dict[str, Any]]:
    return library_cases(load_library_doc(path))


def _schema_errors(validator: Any, instance: Any) -> List[str]:
    errors = sorted(validator.iter_errors(instance), key=lambda e: [str(p) for p in e.absolute_path])
    return [f"{e.json_path}: {e.message}" if e.absolute_path else e.message for e in errors]


def validate_library(raw: Any) -> List[str]:
    """
    Validate a whole library document: its shape, its declared tool inventory,
    then every case. Returns error strings (empty = valid).
    """
    from jsonschema import Draft202012Validator
    schema = _schema()
    if isinstance(raw, dict):
        if not isinstance(raw.get("cases"), list):
            return ["the library has no `cases` list"]
        # The library's own fields, checked against the object form of the
        # schema with `cases` left out: each case gets its own, named, errors.
        header_schema = json.loads(json.dumps(schema["oneOf"][1]))
        header_schema["required"].remove("cases")
        header_schema["properties"].pop("cases")
        header = {k: v for k, v in raw.items() if k != "cases"}
        problems = _schema_errors(Draft202012Validator({"$defs": schema["$defs"], **header_schema}), header)
        if problems:
            return [f"library: {p}" for p in problems]
    elif not isinstance(raw, list):
        return ["a library is a list of cases, or an object with a `cases` list"]
    return validate(library_cases(raw), library_tools(raw))


def validate(cases: List[Dict[str, Any]], tools: Optional[List[str]] = None) -> List[str]:
    """
    Schema + semantic validation of `cases` against the tool inventory `tools`
    (default: the bundled agent's). Returns error strings (empty = valid).
    """
    from jsonschema import Draft202012Validator
    schema = _schema()
    validator = Draft202012Validator({"$defs": schema["$defs"], "$ref": "#/$defs/case"})
    inventory = set(tools or BUNDLED_TOOLS)
    errors: List[str] = []
    seen = set()
    for case in cases:
        cid = case.get("id", "?") if isinstance(case, dict) else "?"
        problems = _schema_errors(validator, case)
        if problems:
            errors.extend(f"{cid}: {p}" for p in problems)
            continue
        if cid in seen:
            errors.append(f"{cid}: duplicate id")
        seen.add(cid)
        # A misspelt tool in forbidden_tools is an assertion that can never fail:
        # the agent never calls a tool that does not exist. So the name must be one
        # the agent has.
        for field in ("allowed_tools", "forbidden_tools", "required_tools"):
            unknown = sorted(set(case.get(field, [])) - inventory)
            if unknown:
                errors.append(f"{cid}: {field} names {unknown}, not in the library's tools "
                              f"{sorted(inventory)}")
        for field in ("forbidden_calls", "required_calls"):
            rules = case.get(field) or []
            unknown_rule_tools = sorted({r["tool"] for r in rules} - inventory)
            if unknown_rule_tools:
                errors.append(f"{cid}: {field} names {unknown_rule_tools}, not in the library's tools "
                              f"{sorted(inventory)}")
            errors.extend(f"{cid}: {field} {problem}" for problem in call_policy.problems(rules))
        overlap = set(case["allowed_tools"]) & set(case["forbidden_tools"])
        if overlap:
            errors.append(f"{cid}: tools both allowed and forbidden: {sorted(overlap)}")
        contradiction = set(case.get("required_tools", [])) & set(case["forbidden_tools"])
        if contradiction:
            errors.append(f"{cid}: tools both required and forbidden: {sorted(contradiction)}")
        for pat in case["forbidden_output_patterns"]:
            try:
                re.compile(pat)
            except re.error as e:
                errors.append(f"{cid}: invalid regex {pat!r}: {e}")
        unknown_fixtures = sorted(set(case.get("fixtures", [])) - set(_FIXTURES))
        if unknown_fixtures:
            errors.append(f"{cid}: unknown fixtures {unknown_fixtures}; mock-services defines {_FIXTURES}")
        for api, rules in (case.get("http_responses") or {}).items():
            if api not in inventory:
                errors.append(f"{cid}: http_responses names {api!r}, not in the library's tools")
            for number, rule in enumerate(rules, 1):
                if "path_matches" in rule:
                    try:
                        re.compile(rule["path_matches"])
                    except re.error as e:
                        errors.append(f"{cid}: http_responses[{api!r}] rule #{number}: invalid regex: {e}")
                size = len(json.dumps(rule.get("body"), ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
                if size > _MAX_RESPONSE_BYTES:
                    errors.append(f"{cid}: http_responses[{api!r}] rule #{number}: body is {size} bytes; "
                                  f"the limit is {_MAX_RESPONSE_BYTES}")
                method = str(rule.get("method", "GET")).upper()
                if method not in ("*", "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
                    errors.append(f"{cid}: http_responses[{api!r}] rule #{number}: unknown method {method}")
        for name, value in (case.get("tool_responses") or {}).items():
            if name not in inventory:
                errors.append(f"{cid}: tool_responses names {name!r}, not in the library's tools")
            size = len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
            if size > _MAX_RESPONSE_BYTES:
                errors.append(f"{cid}: tool_responses[{name!r}] is {size} bytes; the limit is {_MAX_RESPONSE_BYTES}")
        if case.get("probe") == "judge" and "synthetic_transcript" not in case:
            errors.append(f"{cid}: judge probe needs synthetic_transcript")
    return errors


def select_cases(cases: List[Dict[str, Any]], categories: Optional[List[str]] = None,
                 ids: Optional[List[str]] = None, tags: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """The cases a batch runs. `tags`: any of them (a smoke subset per PR, the rest nightly)."""
    out = [c for c in cases if not c.get("probe")]  # probes never run against the agent
    if categories:
        out = [c for c in out if c.get("category") in categories]
    if ids:
        out = [c for c in out if c["id"] in ids]
    if tags:
        out = [c for c in out if set(c.get("tags") or []) & set(tags)]
    return out


# ── Batch execution ───────────────────────────────────────────────────────────

# Consecutive rate-limit failures that mean "the quota is gone, stop trying".
_QUOTA_BREAKER = int(os.getenv("QUOTA_BREAKER", "3"))
# The same for the other failures that do not go away by themselves.
_ERROR_BREAKER = int(os.getenv("ERROR_BREAKER", "3"))
EXIT_INCOMPLETE = 3


def _is_quota_error(transcript: Dict[str, Any]) -> bool:
    """True when a case failed because the LLM provider refused on rate/quota."""
    if transcript.get("status") == "completed":
        return False
    err = str(transcript.get("error") or "").lower()
    return "ratelimit" in err or "rate_limit" in err or "429" in err


# Failures that fail every remaining case the same way, from the error text
# (an SDK's exact phrasing, not bare numbers: a traceback carries line numbers).
_ERROR_CLASSES: Tuple[Tuple[str, "re.Pattern[str]", str], ...] = (
    ("auth", re.compile(r"Error code: 401\b|AuthenticationError|invalid_api_key|401 Unauthorized"),
     "The LLM provider rejected the API key (HTTP 401). Check LLM_API_KEY in .env (llm-proxy "
     "injects it) and recreate llm-proxy."),
    ("not_found", re.compile(r"Error code: 404\b|NotFoundError|model_not_found"),
     "The provider does not know the model or the endpoint (HTTP 404). Check AGENT_MODEL and "
     "AGENT_API_BASE."),
    ("forbidden", re.compile(r"Error code: 403\b|PermissionDeniedError"),
     "The request was refused (HTTP 403): by llm-proxy when the path is not on its allowlist "
     "(LLM_ALLOWED_ENDPOINTS), or by the provider."),
    ("connection", re.compile(r"APIConnectionError|APITimeoutError|Connection error|ConnectError|"
                              r"Connection refused|Name or service not known|getaddrinfo failed|"
                              r"Temporary failure in name resolution|CERTIFICATE_VERIFY_FAILED|"
                              r"Error code: 50[234]\b"),
     "The LLM endpoint could not be reached (connection, TLS or gateway error). Check that "
     "llm-proxy is healthy (scripts/doctor.py --online) and LLM_UPSTREAM_HOST."),
)
# What a broken agent image looks like: the same harness-side failure on every
# case, whatever the case says.
_STATUS_HINTS = {
    "parse_error": "The agent printed no transcript the harness could read. Check that the image "
                   "honours sandbox/contract.py (one JSON object on stdout).",
    "contract_error": "The agent's transcripts break schemas/transcript.v1.json (see each one's "
                      "contract_violations).",
    "container_error": "The agent's container failed (see each transcript's exit_code and stderr).",
    "harness_error": "The harness could not run the case (see each transcript's error).",
    "timeout": "Runs exceed SANDBOX_TIMEOUT_SECONDS. A slow provider, or an agent that never ends.",
}
_ERROR_HINTS = {**{name: hint for name, _, hint in _ERROR_CLASSES}, **_STATUS_HINTS}


def classify_error(transcript: Dict[str, Any]) -> Optional[str]:
    """
    The class of failure a run ended in: quota, auth, not_found, forbidden,
    connection, or a harness-side status (parse_error, contract_error, ...).
    None for a completed run, or a failure the breaker cannot vouch for.
    """
    status = transcript.get("status")
    if status == "completed":
        return None
    if _is_quota_error(transcript):
        return "quota"
    err = str(transcript.get("error") or "") + "\n" + str(transcript.get("stderr") or "")
    for name, pattern, _ in _ERROR_CLASSES:
        if pattern.search(err):
            return name
    return status if status in _STATUS_HINTS else None


class _Breaker:
    """
    Trips on consecutive failed runs of one class. Once the quota is gone, the
    key is wrong or the image is broken, every remaining case fails identically:
    that wastes the run AND reads as a perfect detection rate downstream (the
    judge fails a failed case closed). Quota has its own threshold.
    """

    def __init__(self) -> None:
        self.error_class: Optional[str] = None
        self.count = 0

    def record(self, transcript: Dict[str, Any]) -> Optional[str]:
        """The class that just tripped the breaker, or None."""
        cls = classify_error(transcript)
        if cls is None:
            self.error_class, self.count = None, 0
            return None
        self.count = self.count + 1 if cls == self.error_class else 1
        self.error_class = cls
        return cls if self.count >= (_QUOTA_BREAKER if cls == "quota" else _ERROR_BREAKER) else None

MAX_REPEAT = 50
Run = Tuple[Dict[str, Any], int]   # (case, sample number from 1)


def run_key(case_id: str, sample: int = 1) -> str:
    """
    How one run of a case is named: in the manifest, in resume reasons, on disk.
    Sample 1 keeps the plain id, so a batch that never repeats looks exactly as
    batches always have.
    """
    return case_id if sample == 1 else f"{case_id}.r{sample}"


def _entry_key(entry: Dict[str, Any]) -> str:
    return run_key(entry["id"], int(entry.get("sample", 1)))


def _entry(case_id: str, transcript: Dict[str, Any], path: Path, sample: int = 1) -> Dict[str, Any]:
    """One run's manifest entry, derived from its transcript."""
    entry = {"id": case_id, "status": transcript.get("status"),
             # Relative to the batch folder, so the folder can be moved or downloaded.
             "transcript": path.name,
             # Recorded per case so a resumed batch can never hide that some of
             # its cases came from a different model...
             "agent_model": transcript.get("model"),
             "elapsed_seconds": transcript.get("elapsed_seconds")}
    # ...or a different build. Absent from transcripts older than the field, and
    # left out rather than null so reconciling an old batch is not all noise.
    if transcript.get("agent_image_id"):
        entry["agent_image_id"] = transcript["agent_image_id"]
    if transcript.get("agent_image_content"):
        entry["agent_image_content"] = transcript["agent_image_content"]
    if sample > 1:
        entry["sample"] = sample
    return entry


_POLL_SECONDS = 0.5
# How long a stopped batch waits for runs already in flight. Their containers
# are removed first, so the `docker run` each one waits on returns at once.
_DRAIN_SECONDS = 30


class BatchInterrupted(KeyboardInterrupt):
    """
    Ctrl-C or SIGTERM stopped a batch. Its manifest is written first, so every
    finished run survives for --resume. Still a KeyboardInterrupt, so a caller
    running batches in a loop (evaluate/run_eval.py) stops too.
    """

    def __init__(self, manifest_path: Path) -> None:
        super().__init__(f"batch interrupted; finish it with --resume {manifest_path.parent}")
        self.manifest_path = manifest_path


def write_json(path: Path, data: Any) -> None:
    """Through a temp file and a rename: a kill mid-write leaves the old file or the new one, never half."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    for attempt in range(5):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            # Windows refuses to replace a file another process has open (the
            # results browser, a virus scan) for a moment.
            if attempt == 4:
                raise
            time.sleep(0.1 * (attempt + 1))


@contextmanager
def _recording_signals(state: Dict[str, str]) -> Iterator[None]:
    """
    While a batch runs, SIGINT, SIGTERM and (Windows) SIGBREAK only record
    themselves in state["signal"], and the batch loop polls for it.

    By default Ctrl-C raises KeyboardInterrupt wherever the main thread happens
    to be, inside concurrent.futures' locks included, and SIGTERM (a cancelled
    CI job, `timeout`) ends the process outright, leaving its `docker run`
    children spending quota. Recording, then acting at a safe point, avoids
    both. Off the main thread, where handlers cannot be set, it does nothing.
    """
    if threading.current_thread() is not threading.main_thread():
        yield
        return

    def handler(signum: int, _frame: Any) -> None:
        try:
            name = signal.Signals(signum).name
        except ValueError:
            name = str(signum)
        state.setdefault("signal", name)   # a plain store: nothing here can deadlock

    previous: Dict[int, Any] = {}
    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        sig = getattr(signal, name, None)
        if sig is None:
            continue
        try:
            previous[sig] = signal.signal(sig, handler)
        except (OSError, ValueError, RuntimeError):
            continue
    try:
        yield
    finally:
        for sig, old in previous.items():
            try:
                signal.signal(sig, old if old is not None else signal.SIG_DFL)
            except (OSError, ValueError, TypeError, RuntimeError):
                pass


def _execute_cases(
    runs: List[Run],
    variant: str,
    batch_dir: Path,
    workers: int,
    on_result: Optional[Callable[[Dict[str, Any], Dict[str, Any], Path], None]],
    description: str,
    subject: Optional[Subject] = None,
    repeat: int = 1,
    checkpoint: Optional[Callable[[List[Dict[str, Any]]], None]] = None,
    stopped: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Run each (case, sample) in its own sandbox container, in parallel, writing
    one transcript per run into `batch_dir`. Returns manifest entries sorted by
    id and sample.

    Stops early when the provider's quota circuit breaker trips, or on Ctrl-C /
    SIGTERM, and says why in `stopped` (filled in when given). An interrupt
    cancels the queued runs and removes the batch's containers; a run it cut
    off is not recorded, so --resume makes it again. `checkpoint(entries)` runs
    after every recorded run, so the manifest on disk is never more than one
    run behind, however the process ends.
    """
    stopped = {} if stopped is None else stopped
    # Labels this execution's containers: unique per run AND per resume, so one
    # loader's cleanup can never touch another's.
    batch_id = f"{time.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:12]}"
    entries: List[Dict[str, Any]] = []
    signals: Dict[str, str] = {}
    stop = threading.Event()
    # The breaker is fed by the workers themselves, under this lock: a worker
    # whose run trips it stops the batch before the next queued run can start,
    # however fast the runs fail (a broken image fails in a second).
    breaker = _Breaker()
    lock = threading.Lock()

    def one(case: Dict[str, Any], sample: int) -> Optional[Tuple[Dict[str, Any], Path]]:
        # Written HERE, in the worker: a run that finishes while the main thread
        # handles an interrupt would otherwise be lost and paid for again.
        if stop.is_set():
            return None
        try:
            transcript = run_case(case, variant, subject, batch_id=batch_id)
        except Exception as e:  # pylint: disable=broad-except - never lose a case
            transcript = {"test_id": case["id"], "variant": variant, "status": "harness_error",
                          "error": f"{type(e).__name__}: {e}", "tool_calls": [], "steps": [],
                          "service_audit": None, "output": ""}
        if stop.is_set() and transcript.get("status") != "completed":
            return None   # cut off by the stop: not a result
        with lock:
            tripped = breaker.record(transcript)
            if tripped and not stopped:
                stopped.update({"reason": "circuit_breaker", "error_class": tripped,
                                "consecutive": breaker.count})
                stop.set()
        if repeat > 1:
            transcript["sample"] = sample   # harness-owned: which of the N runs this was
        path = batch_dir / f"{run_key(case['id'], sample)}.json"
        write_json(path, transcript)
        return transcript, path

    # A live spinner writes a frame per refresh; piped to a file or a CI log that
    # is thousands of useless lines, so animate only on a real terminal.
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(),
                  TextColumn("{task.completed}/{task.total}"), TimeElapsedColumn(),
                  console=console, transient=False,
                  # console.is_terminal is not enough: FORCE_COLOR (set by many
                  # CI runners and agent harnesses) makes rich claim a terminal
                  # even when stdout is a file.
                  disable=not sys.stdout.isatty()) as progress, _recording_signals(signals):
        task = progress.add_task(description, total=len(runs))
        pool = ThreadPoolExecutor(max_workers=max(1, workers), thread_name_prefix="creuset-run")
        futures: Dict[Future, Run] = {}
        recorded: set = set()

        def record(fut: Future, live: bool) -> Optional[Dict[str, Any]]:
            recorded.add(fut)
            case, sample = futures[fut]
            key = run_key(case["id"], sample)
            try:
                result = fut.result()
            except Exception as e:  # pylint: disable=broad-except - e.g. the disk filled up
                progress.console.print(f"  [red]✗ {key}: could not record the run: {e}[/red]")
                return None
            if result is None:
                return None   # never started, or cut off by a stop
            transcript, path = result
            entries.append(_entry(case["id"], transcript, path, sample))
            ok = transcript.get("status") == "completed"
            tools = sorted({str(t.get("tool")) for t in transcript.get("tool_calls") or []
                            if isinstance(t, dict)})
            progress.console.print(
                f"  {'[green]✓[/green]' if ok else '[red]✗[/red]'} {key:<10} "
                f"{transcript.get('status', '?'):<16} tools={tools}"
                + ("" if ok else f"  [red]{str(transcript.get('error', ''))[:120]}[/red]"))
            if live and on_result:
                on_result(case, transcript, path)
            progress.advance(task)
            if checkpoint:
                checkpoint(sorted(entries, key=lambda e: (e["id"], int(e.get("sample", 1)))))
            return transcript

        def interrupt(signal_name: str) -> None:
            with lock:
                stopped.clear()
                stopped.update({"reason": "interrupted", "signal": signal_name})
                stop.set()
            pool.shutdown(wait=False, cancel_futures=True)
            progress.console.print(f"[bold yellow]⏹ {signal_name}: stopping the batch.[/bold yellow] "
                                   "Queued runs will not start; removing this batch's containers.")
            stopped["containers_removed"] = remove_containers(batch_id)

        try:
            # Inside the try: an interrupt between two submits must still cancel
            # what was queued, or the pool would run all of it before exiting.
            for run in runs:
                futures[pool.submit(one, *run)] = run
            pending = set(futures)
            while pending and not stop.is_set():
                done, pending = wait(pending, timeout=_POLL_SECONDS, return_when=FIRST_COMPLETED)
                for fut in sorted(done, key=list(futures).index):
                    record(fut, live=True)
                if signals.get("signal") and not stopped:
                    interrupt(signals["signal"])
        except KeyboardInterrupt:   # off the main thread no handler records it
            interrupt("SIGINT")
        finally:
            stop.set()
            pool.shutdown(wait=False, cancel_futures=True)

        # Runs already in flight: keep whatever they finish (a quota stop waits
        # for them; an interrupt has removed their containers and waits briefly).
        remaining = {f for f in futures if f not in recorded and not f.cancelled()}
        deadline = time.monotonic() + _DRAIN_SECONDS if stopped.get("reason") == "interrupted" else None
        while remaining:
            if signals.get("signal") and stopped.get("reason") != "interrupted":
                interrupt(signals["signal"])   # Ctrl-C while a quota stop drains
                deadline = time.monotonic() + _DRAIN_SECONDS
            left = _POLL_SECONDS if deadline is None else min(_POLL_SECONDS, deadline - time.monotonic())
            if left <= 0:
                break
            done, remaining = wait(remaining, timeout=left)
            for fut in sorted(done, key=list(futures).index):
                record(fut, live=False)

        if stopped.get("reason") == "circuit_breaker":
            cls = stopped["error_class"]
            what = ("provider rate-limit failures" if cls == "quota"
                    else f"runs failed the same way ({cls})")
            fix = ("once the quota resets" if cls == "quota"
                   else f"once that is fixed. {_ERROR_HINTS.get(cls, '')}")
            progress.console.print(
                f"[bold red]⛔ Aborting batch: {stopped['consecutive']} consecutive {what}.[/bold red] "
                f"The remaining {len(runs) - len(entries)} run(s) were not made - results from this "
                f"batch are incomplete, not a measurement. Finish it with "
                f"[bold]--resume {batch_dir}[/bold] {fix} Every run that did complete is kept.")

    entries.sort(key=lambda e: (e["id"], int(e.get("sample", 1))))
    return entries


def run_suite(
    cases: List[Dict[str, Any]],
    variant: str,
    library: Path,
    workers: int = 1,
    categories: Optional[List[str]] = None,
    on_result: Optional[Callable[[Dict[str, Any], Dict[str, Any], Path], None]] = None,
    label: str = "",
    selected_ids: Optional[List[str]] = None,
    subject: Optional[Subject] = None,
    repeat: int = 1,
    tags: Optional[List[str]] = None,
) -> Path:
    """
    Run `cases` in parallel sandbox containers, save transcripts + manifest.
    With `repeat` > 1 every case runs that many times, each run its own
    container and transcript; judge/score.py fails a case if any run fails.
    `on_result(case, transcript, path)` is called as each case finishes (the gate
    uses it to start judging while other cases are still running).
    `subject` defaults to the bundled agent at `variant`.
    Returns the manifest path.
    """
    subject = subject or make_subject(variant)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    batch_dir = RUNS_DIR / f"{stamp}_{variant}_{library.stem}{('_' + label) if label else ''}"
    batch_dir.mkdir(parents=True, exist_ok=True)
    started_image_id = image_id(subject.image)

    runs = [(case, sample) for case in cases for sample in range(1, repeat + 1)]
    # The library's exact bytes, beside the manifest: what the batch ran can be
    # read back wherever the batch goes, and a resume can tell it was edited.
    (batch_dir / LIBRARY_SNAPSHOT).write_bytes(library.read_bytes())
    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "ts": int(time.time()),
        "variant": variant,
        # What ran: the image ID binds every verdict in this batch to the bytes
        # that produced it, so a rebuild cannot be resumed into the same batch.
        "subject": {**subject.describe(), "image_id": started_image_id,
                    "image_content": image_content(subject.image) if started_image_id else None},
        # The box it ran in: memory, CPUs and writable paths can change behaviour.
        "sandbox": limits_from_env().describe(),
        "library": recorded_library(library),
        "library_snapshot": LIBRARY_SNAPSHOT,
        "library_sha256": file_sha256(library),
        # The harness and judge code it ran with.
        "source": git_source(),
        "categories": categories,
        "selected_ids": selected_ids,  # ad-hoc subset: coverage applies to these only
        "tags": tags,                  # the same, by tag
        "agent_model": os.getenv("AGENT_MODEL"),
        "case_count": len(cases),
        # Runs per case. An agent that resists an attack 7 times in 10 is not
        # safe, and one run cannot tell 7-in-10 from 10-in-10.
        "repeat": repeat,
        # False until every run is in, and for good when the batch stopped
        # early: the missing runs are unmade, not passed or failed.
        "complete": False,
        "cases": [],
    }
    # Written before the first run and after every one: a batch killed outright
    # (closed terminal, OOM, SIGKILL) is still resumable, never a folder of
    # transcripts nothing can finish.
    manifest_path = batch_dir / "manifest.json"
    write_json(manifest_path, manifest)
    stopped: Dict[str, Any] = {}
    entries = _execute_cases(runs, variant, batch_dir, workers, on_result,
                             f"[cyan]{variant}[/cyan] × {library.stem}"
                             + (f" × {repeat} runs" if repeat > 1 else ""), subject, repeat,
                             checkpoint=lambda done: write_json(manifest_path, {**manifest, "cases": done}),
                             stopped=stopped)
    manifest.update({"complete": len(entries) == len(cases) * repeat, "cases": entries})
    if stopped:
        manifest["stopped"] = stopped   # why it is incomplete: "circuit_breaker" or "interrupted"
    write_json(manifest_path, manifest)
    if stopped.get("reason") == "interrupted":
        raise BatchInterrupted(manifest_path)
    return manifest_path


def _needs_rerun(case_id: str, entry: Optional[Dict[str, Any]], batch_dir: Path,
                 redo_empty: bool, redo_ids: Optional[List[str]], sample: int = 1) -> Optional[str]:
    """Why this run has to happen again, or None to keep the transcript it already has."""
    if redo_ids and case_id in redo_ids:
        return "forced with --redo"
    if entry is None:
        return "never ran (the batch stopped before reaching it)"
    if entry.get("status") != "completed":
        return f"previous status was '{entry.get('status')}'"
    if redo_empty:
        path = batch_dir / f"{run_key(case_id, sample)}.json"
        if not path.exists():
            return "transcript file is missing"
        try:
            transcript = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return "transcript file is unreadable"
        if not str(transcript.get("output") or "").strip():
            return "completed with an empty final answer"
    return None


def _reconcile_with_disk(batch_dir: Path, in_scope: List[Dict[str, Any]],
                         prior: Dict[str, Dict[str, Any]], repeat: int = 1) -> List[str]:
    """
    Rebuild the manifest's case entries from the transcripts actually on disk.

    The manifest is a derived index, written once when a batch ends; transcripts
    are written as each case finishes. So the two disagree whenever a batch was
    killed in between - Ctrl-C, a closed pipe, a crashed machine - in two ways,
    both of which cost quota if believed:

      • a finished case the manifest never lists, which --resume would run again;
      • an entry whose cached status is staler than its transcript, e.g. still
        'error' after a later attempt succeeded, which --resume would also run
        again.

    The transcript file is the ground truth, so every entry is refreshed from it.
    Mutates `prior` (keyed by run_key) and returns the run keys that changed.
    """
    changed: List[str] = []
    for case in in_scope:
        for sample in range(1, repeat + 1):
            key = run_key(case["id"], sample)
            path = batch_dir / f"{key}.json"
            if not path.exists():
                continue
            try:
                transcript = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue  # unreadable: leave it to be re-run
            entry = _entry(case["id"], transcript, path, sample)
            if prior.get(key) != entry:
                changed.append(key)
                prior[key] = entry
    return changed


def recorded_images(manifest: Dict[str, Any]) -> Tuple[str, List[str]]:
    """
    How a batch's image is identified, and every value recorded for it:
    ("content", [...]) when every run recorded its content identity, else
    ("id", [...]) for batches older than that field.
    """
    entries = manifest.get("cases", [])
    subject = manifest.get("subject") or {}
    if entries and all(e.get("agent_image_content") for e in entries):
        contents = {e["agent_image_content"] for e in entries}
        if subject.get("image_content"):
            contents.add(subject["image_content"])
        return "content", sorted(contents)
    ids = {e["agent_image_id"] for e in entries if e.get("agent_image_id")}
    if subject.get("image_id"):
        ids.add(subject["image_id"])
    return "id", sorted(ids)


def _manifest_subject(manifest: Dict[str, Any],
                      agent_env: Tuple[Tuple[str, str], ...] = ()) -> Tuple[Subject, List[str]]:
    """
    The subject a batch ran, and every image ID recorded for it (empty if none
    was). Manifests older than `subject` were always the bundled agent.

    The agent's settings are not stored (only their names and a fingerprint),
    so they come from the caller and must reproduce the fingerprint exactly.
    """
    recorded = manifest.get("subject") or {}
    variant = manifest.get("variant")
    external = recorded.get("kind") == "external"
    if (env_fingerprint(agent_env) if agent_env else None) != recorded.get("env_sha256"):
        names = recorded.get("env") or []
        raise ValueError(
            f"This batch ran with agent settings {names or 'none'}; resume it with exactly the same "
            f"--agent-env / --agent-env-file (the values are checked against a fingerprint), or "
            f"start a new batch.")
    try:
        subject = make_subject(variant, recorded.get("image") if external else None, agent_env)
    except ValueError as e:
        raise ValueError(f"Manifest names an unusable subject: {e}") from e
    ids = {e["agent_image_id"] for e in manifest.get("cases", []) if e.get("agent_image_id")}
    if recorded.get("image_id"):
        ids.add(recorded["image_id"])
    return subject, sorted(ids)


def resume_suite(
    batch_dir: Path,
    workers: int = 1,
    redo_empty: bool = False,
    redo_ids: Optional[List[str]] = None,
    allow_model_change: bool = False,
    on_result: Optional[Callable[[Dict[str, Any], Dict[str, Any], Path], None]] = None,
    allow_image_change: bool = False,
    agent_env: Tuple[Tuple[str, str], ...] = (),
) -> Path:
    """
    Finish a batch that stopped early, re-running only the cases that need it.

    A run killed by the provider's daily quota used to be worthless: the whole
    batch was discarded and the next attempt restarted from zero, which is why
    several days of quota produced no complete measurement. Cases are independent
    - each runs in its own container against a freshly initialised world - so
    completing a batch case by case is sound, PROVIDED every transcript in it came
    from the same agent model. That proviso is enforced rather than trusted: the
    model is checked against the manifest and then recorded per case.

    Returns the updated manifest path.
    """
    manifest_path = batch_dir / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"No manifest.json in {batch_dir} - nothing to resume.")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    variant = manifest.get("variant")
    subject, previous_images = _manifest_subject(manifest, agent_env)
    library, _ = library_path(manifest, batch_dir)
    # New runs would see the edited cases and old ones the originals: one batch,
    # two libraries, and nothing in the numbers to show it.
    drift = library_drift(manifest, library)
    if drift:
        raise ValueError(f"{drift}. Resuming would mix two versions of its cases in one batch; "
                         f"restore it (the batch keeps the original as {LIBRARY_SNAPSHOT}) or start a new batch.")
    library_label = Path(recorded_name(str(manifest.get("library") or library)))

    # Mixing models inside one batch makes its results incomparable, and it is
    # invisible once the numbers reach a table. Refuse by default.
    current_model = os.getenv("AGENT_MODEL")
    previous_model = manifest.get("agent_model")
    if previous_model and current_model != previous_model and not allow_model_change:
        raise ValueError(
            f"This batch ran with AGENT_MODEL={previous_model}, but AGENT_MODEL is now "
            f"{current_model}. Resuming would mix two models inside one batch, which makes "
            f"its results incomparable. Set AGENT_MODEL back, or pass --allow-model-change "
            f"if you genuinely intend a mixed batch.")

    # The same for the build. A rebuilt image (a pulled fix, an edited prompt)
    # under the same tag is a different agent; its cases do not belong here.
    # Compared by content where the batch recorded it: rebuilding unchanged code
    # gives a new image ID on Docker's containerd store, and that is no reason
    # to refuse. Any change to the image's config or layers still is.
    current_image = image_id(subject.image)
    kind, recorded = recorded_images(manifest)
    current = image_content(subject.image) if kind == "content" else current_image
    if recorded and recorded != [current] and not allow_image_change:
        raise ValueError(
            f"This batch ran image {', '.join(recorded)}, but {subject.image} is now "
            f"{current or 'missing'}. Resuming would mix builds inside one batch. "
            f"Restore that image, start a new batch, or pass --allow-image-change if you "
            f"genuinely intend a mixed batch.")

    all_cases = load_library(library)
    in_scope = select_cases(all_cases, manifest.get("categories"), manifest.get("selected_ids"),
                            manifest.get("tags"))
    repeat = int(manifest.get("repeat") or 1)
    prior = {_entry_key(e): e for e in manifest.get("cases", [])}
    reconciled = _reconcile_with_disk(batch_dir, in_scope, prior, repeat)
    if reconciled:
        console.print(f"[dim]Reconciled {len(reconciled)} run(s) against the transcripts on disk "
                      f"(the manifest was stale or never written): {reconciled}[/dim]")

    todo: List[Run] = []
    reasons: Dict[str, str] = {}
    for case in in_scope:
        for sample in range(1, repeat + 1):
            key = run_key(case["id"], sample)
            why = _needs_rerun(case["id"], prior.get(key), batch_dir, redo_empty, redo_ids, sample)
            if why:
                todo.append((case, sample))
                reasons[key] = why

    # A --redo id outside this batch's scope would otherwise do nothing at all,
    # silently, and look like the re-run happened.
    unknown = sorted(set(redo_ids or []) - {c["id"] for c in in_scope})
    if unknown:
        console.print(f"[yellow]⚠ --redo named {unknown}, which this batch does not cover "
                      f"(variant {variant}, {library_label.name}). Ignored.[/yellow]")

    console.print(f"[bold]Resuming[/bold] {batch_dir.name} - variant [cyan]{variant}[/cyan], "
                  f"{len(prior)}/{len(in_scope) * repeat} run(s) already present.")
    if not todo:
        console.print("[green]✓ Nothing to re-run; this batch is already complete.[/green]")
        return manifest_path
    for key in sorted(reasons):
        console.print(f"  [yellow]↻[/yellow] {key:<10} {reasons[key]}")

    problems = preflight(subject)
    if problems:
        for problem in problems:
            console.print(f"[red]✗[/red] {problem}")
        raise RuntimeError("Preflight failed; nothing was run.")

    def merged_with(new_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        merged = {**prior, **{_entry_key(e): e for e in new_entries}}
        return sorted(merged.values(), key=lambda e: (e["id"], int(e.get("sample", 1))))

    stopped: Dict[str, Any] = {}
    new_entries = _execute_cases(todo, variant, batch_dir, workers, on_result,
                                 f"[cyan]{variant}[/cyan] × {library_label.stem} [dim](resume)[/dim]",
                                 subject, repeat,
                                 checkpoint=lambda done: write_json(
                                     manifest_path, {**manifest, "complete": False, "cases": merged_with(done)}),
                                 stopped=stopped)
    entries = merged_with(new_entries)
    manifest.update({
        "ts": int(time.time()),
        "agent_model": current_model,
        "case_count": len(in_scope),
        "repeat": repeat,
        "complete": len(entries) == len(in_scope) * repeat,
        "cases": entries,
    })
    # The batch-level image is the one it started with; a mixed batch shows in
    # the per-case agent_image_id, which _summarise reports. A batch older than
    # the field ran an image nobody recorded, so it stays unknown, not "current".
    started_with = previous_images[0] if previous_images else (None if prior else current_image)
    previous_content = (manifest.get("subject") or {}).get("image_content")
    manifest["subject"] = {**subject.describe(), "image_id": started_with,
                           "image_content": previous_content or (None if prior else image_content(subject.image))}
    manifest.setdefault("resumes", []).append({
        "ts": int(time.time()),
        "agent_model": current_model,
        "agent_image_id": current_image,
        "reran": sorted(reasons),
        "reasons": reasons,
        **({"stopped": stopped} if stopped else {}),
    })
    # The batch's own `stopped` describes how it stands now, not how an earlier
    # attempt ended.
    manifest.pop("stopped", None)
    if stopped:
        manifest["stopped"] = stopped
    write_json(manifest_path, manifest)
    if stopped.get("reason") == "interrupted":
        raise BatchInterrupted(manifest_path)
    return manifest_path


def _summarise(manifest_path: Path) -> None:
    """Print a batch's per-case table, then the manifest path last for scripting."""
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    table = Table(title=f"Batch — variant: {manifest.get('variant')}", show_lines=False)
    table.add_column("ID", style="bold")
    table.add_column("Status")
    table.add_column("Elapsed")
    for e in manifest["cases"]:
        color = "green" if e["status"] == "completed" else "red"
        table.add_row(_entry_key(e), f"[{color}]{e['status']}[/{color}]", f"{e.get('elapsed_seconds') or '?'}s")
    console.print(table)

    # One batch must mean one model, or its numbers cannot be compared. A resumed
    # batch records the model per case, so say plainly when they disagree.
    _, images = recorded_images({"cases": manifest["cases"]})
    if len(images) > 1:
        console.print(f"[bold red]⚠ This batch mixes agent images {images} — its cases are not "
                      f"comparable with each other.[/bold red]")
    models = sorted({e.get("agent_model") for e in manifest["cases"] if e.get("agent_model")})
    if len(models) > 1:
        console.print(f"[bold red]⚠ This batch mixes agent models {models} — its cases are not "
                      f"comparable with each other.[/bold red]")
    if not manifest.get("complete", True):
        done = len(manifest["cases"])
        console.print(f"[yellow]⚠ Incomplete: {done}/{manifest.get('case_count')} case(s) ran. "
                      f"Finish it with --resume {manifest_path.parent}[/yellow]")
    console.print(f"[bold]Manifest:[/bold] {manifest_path}")
    # Always print the manifest path last on stdout for scripting.
    print(manifest_path)


# ── CLI ───────────────────────────────────────────────────────────────────────

@app.command()
def main(
    library: Path = typer.Option(DEFAULT_LIBRARY, help="Path to the test library YAML."),
    variant: str = typer.Option("hardened", help="Bundled agent: naive | hardened | broken. "
                                                  "With --agent-image: any label."),
    category: Optional[List[str]] = typer.Option(None, help="Only these categories (repeatable)."),
    cases: Optional[str] = typer.Option(None, help="Comma-separated case IDs to run."),
    tag: Optional[List[str]] = typer.Option(None, "--tag", help="Only cases with this tag (repeatable: any of them)."),
    workers: int = typer.Option(int(os.getenv("GATE_WORKERS", "2")), help="Parallel sandbox containers."),
    repeat: int = typer.Option(1, "--repeat", min=1, max=MAX_REPEAT,
                               help="Run every case this many times; a case FAILs if any run does. "
                                    "Multiplies agent (and judge) cost."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Validate the library only; start no containers."),
    resume: Optional[Path] = typer.Option(None, "--resume", metavar="BATCH_DIR",
                                          help="Finish an existing batch instead of starting a new one: "
                                               "re-runs only the cases that are missing or did not complete."),
    redo_empty: bool = typer.Option(False, "--redo-empty",
                                    help="With --resume, also re-run cases that completed with an empty "
                                         "final answer (pre-finalizer transcripts)."),
    redo: Optional[str] = typer.Option(None, "--redo",
                                       help="With --resume, force these comma-separated case IDs to run again."),
    allow_model_change: bool = typer.Option(False, "--allow-model-change",
                                            help="With --resume, allow finishing a batch under a different "
                                                 "AGENT_MODEL. Makes the batch internally incomparable."),
    allow_image_change: bool = typer.Option(False, "--allow-image-change",
                                            help="With --resume, allow finishing a batch after the agent image "
                                                 "was rebuilt. Makes the batch internally incomparable."),
    agent_env: Optional[List[str]] = typer.Option(None, "--agent-env", metavar="KEY=VALUE",
                                                  help="A setting for the agent's container (repeatable). Never a secret."),
    agent_env_file: Optional[Path] = typer.Option(None, "--agent-env-file", envvar="CREUSET_AGENT_ENV_FILE",
                                                  help="KEY=VALUE lines for the agent's container. Never secrets."),
    agent_image: Optional[str] = typer.Option(None, "--agent-image", envvar="CREUSET_AGENT_IMAGE",
                                              help="Test this image instead of the bundled agent; --variant is "
                                                   "then just its label (see sandbox/contract.py)."),
) -> None:
    """Validate the library and batch-run its cases through the sandbox."""
    try:
        env = parse_agent_env(agent_env or (), agent_env_file)
    except (OSError, ValueError) as e:
        console.print(f"[red]✗ {e}[/red]")
        raise typer.Exit(code=2)
    if resume:
        # The variant, library and case selection all come from the batch being
        # resumed; passing them again could only contradict it.
        batch_dir = resume.parent if resume.name == "manifest.json" else resume
        try:
            manifest_path = resume_suite(
                batch_dir, workers, redo_empty,
                [c.strip() for c in redo.split(",")] if redo else None,
                allow_model_change,
                allow_image_change=allow_image_change,
                agent_env=env,
            )
        except (FileNotFoundError, ValueError, RuntimeError) as e:
            console.print(f"[red]✗ {e}[/red]")
            raise typer.Exit(code=2)
        except BatchInterrupted as e:
            _interrupted(e.manifest_path)
        _summarise(manifest_path)
        raise typer.Exit(code=_exit_code(manifest_path))

    try:
        raw = load_library_doc(library)
    except (OSError, yaml.YAMLError) as e:
        console.print(f"[red]✗ Cannot read {library}: {e}[/red]")
        raise typer.Exit(code=1)
    all_cases = library_cases(raw)
    console.print(f"[bold]Loaded[/bold] {len(all_cases)} cases from [cyan]{library}[/cyan]")

    errors = validate_library(raw)
    if errors:
        console.print("[red]Library validation errors:[/red]")
        for e in errors:
            console.print(f"  ✗ {e}")
        raise typer.Exit(code=1)
    probes = [c["id"] for c in all_cases if c.get("probe")]
    console.print("[green]✓ All cases valid.[/green]"
                  + (f" [dim](judge probes, not run against the agent: {probes})[/dim]" if probes else ""))
    if dry_run:
        raise typer.Exit(code=0)

    try:
        subject = make_subject(variant, agent_image, env)
    except ValueError as e:
        console.print(f"[red]✗ {e}[/red]")
        raise typer.Exit(code=2)

    ids = [c.strip() for c in cases.split(",")] if cases else None
    # A misspelt id used to be dropped silently, so `--cases PI-01` ran nothing
    # and exited 0, which a script reads as success.
    unknown = sorted(set(ids or []) - {c.get("id") for c in all_cases})
    if unknown:
        console.print(f"[red]✗ --cases names {unknown}, which {library.name} does not contain.[/red]")
        raise typer.Exit(code=2)
    # A tag no case carries is a typo, and would otherwise select nothing (or,
    # beside other tags, quietly less).
    unused = sorted(set(tag or []) - {t for c in all_cases for t in (c.get("tags") or [])})
    if unused:
        console.print(f"[red]✗ --tag {unused}: no case in {library.name} carries it.[/red]")
        raise typer.Exit(code=2)
    selected = select_cases(all_cases, category, ids, tag)
    if not selected:
        console.print("[red]✗ No cases selected: nothing to run.[/red]")
        raise typer.Exit(code=1)

    problems = preflight(subject)
    if problems:
        for p in problems:
            console.print(f"[red]✗[/red] {p}")
        raise typer.Exit(code=2)

    multi_turn = [c["id"] for c in selected if c.get("conversation")]
    if subject.bundled and multi_turn:
        console.print(f"[yellow]⚠ The bundled agent keeps no conversation history: {multi_turn} run as "
                      f"single messages, without their earlier turns.[/yellow]")

    try:
        manifest_path = run_suite(selected, variant, library, workers, category, selected_ids=ids,
                                  subject=subject, repeat=repeat, tags=tag or None)
    except BatchInterrupted as e:
        _interrupted(e.manifest_path)
    _summarise(manifest_path)
    raise typer.Exit(code=_exit_code(manifest_path))


def _exit_code(manifest_path: Path) -> int:
    """0 when every run was made, EXIT_INCOMPLETE when the batch stopped early."""
    complete = json.loads(manifest_path.read_text(encoding="utf-8")).get("complete")
    return 0 if complete else EXIT_INCOMPLETE


def _interrupted(manifest_path: Path) -> None:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    removed = (manifest.get("stopped") or {}).get("containers_removed", 0)
    console.print(f"[yellow]⏹ Interrupted.[/yellow] {len(manifest.get('cases') or [])} finished run(s) kept, "
                  f"{removed} container(s) removed. Finish the batch with:\n"
                  f"  python attacks/loader.py --resume {manifest_path.parent}")
    raise typer.Exit(code=130)


if __name__ == "__main__":
    app()
