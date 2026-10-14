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
  python attacks/loader.py --variant hardened --tag smoke

  # Another agent image, batches somewhere else, manifest path for a script
  python attacks/loader.py --variant mine --image my-agent:1.2 --batch-dir out/runs \
      --manifest-out out/manifest.txt

  # Finish a batch the provider's quota (or Ctrl-C) cut short: re-runs only
  # what is missing or did not complete
  python attacks/loader.py --resume logs/runs/<batch>
  python attacks/loader.py --resume logs/runs/<batch> --redo-empty

Output (one folder per batch, movable as a unit):
  logs/runs/<timestamp>_<variant>_<library>/
      <ID>.json          one transcript per case, written as each case finishes
      library.yaml       byte-for-byte copy of the library the batch ran
      manifest.json      what ran → consumed by judge/score.py (paths inside
                         are relative to this folder)

Exit codes:
  0  the batch is complete and every case completed
  1  --dry-run only: the library is invalid
  2  usage or configuration error; nothing was run (unknown --cases id,
     nothing selected, bad variant, missing image, preflight failure)
  3  the batch is incomplete (quota, circuit breaker, Ctrl-C) or a case did
     not complete — its numbers are not a measurement yet; finish it with --resume
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple

import jsonschema
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
from run_test import is_bundled_image, preflight, resolve_image, run_case, validate_variant  # noqa: E402

try:
    from run_test import remove_batch_containers  # noqa: E402
except ImportError:  # a sandbox/run_test.py that does not label its containers
    def remove_batch_containers(batch_id: str) -> int:
        """Without batch labels there is nothing to find the containers by."""
        console.print("[yellow]⚠ This sandbox/run_test.py cannot remove a batch's containers by "
                      "label; check `docker ps` for leftover creuset-test-* containers.[/yellow]")
        return 0

app = typer.Typer(add_completion=False)
console = Console()

DEFAULT_LIBRARY = _ROOT / "attacks" / "attack_library.yaml"
RUNS_DIR = _ROOT / "logs" / "runs"
CASE_SCHEMA_PATH = _ROOT / "schemas" / "case.v1.json"
MANIFEST_SCHEMA_VERSION = 1
LIBRARY_SNAPSHOT = "library.yaml"

# The tools the bundled agent (agent/tools.py) offers. Case tool names are no
# longer limited to these (another agent has other tools), so a run against the
# bundled image checks them instead: a forbidden tool it does not have, say a
# typo like `send_mail`, can never be called, and its check would pass vacuously.
BUNDLED_TOOLS: Tuple[str, ...] = ("send_email", "delete_file", "charge_payment",
                                  "query_database", "read_file", "list_files")
# Fixtures are Python compiled into the mock-services image; the allowlist must
# match sandbox/mock_services/main.py _FIXTURES (tests/test_catalogue_consistency.py).
_FIXTURES = ["poisoned_db_record", "poisoned_filename", "base64_metadata", "cleanup_notice",
             "pipeline_maintenance"]

# ── Schema ────────────────────────────────────────────────────────────────────

# Every rule here is a superset of the one before it, so a library that
# validated before still validates. The id ends up in a file name and a
# container name, which is why it stays this narrow.
CASE_ID_PATTERN = r"^[A-Z][A-Z0-9_]{1,15}-\d{3,5}$"
TOOL_NAME_PATTERN = r"^[a-z][a-z0-9_]{0,63}$"  # = mock-services' generic /tools/{name}
TAG_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$"
# mock-services' own bounds for canned responses (main.py _MAX_RESPONSES,
# _MAX_JSON_BYTES): a case over them would validate here and 400 at run time.
MAX_MOCK_RESPONSES = 64
MAX_MOCK_RESPONSE_BYTES = 64 * 1024

_TOOL_LIST = {"type": "array", "items": {"type": "string", "pattern": TOOL_NAME_PATTERN}}
CASE_SCHEMA: Dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "urn:creuset:schema:case:v1",
    "title": "Creuset test case, version 1",
    "description": ("One entry of a library's top-level `cases:` list (attacks/*.yaml). Exported "
                    "from attacks/loader.py CASE_SCHEMA, which is what `loader.py --dry-run` "
                    "checks; regenerate with `python attacks/loader.py --export-schema`."),
    "type": "object",
    "required": ["id", "category", "severity", "scenario", "input_payload",
                 "expected_behavior", "allowed_tools", "forbidden_tools",
                 "forbidden_output_patterns"],
    "properties": {
        "id": {"type": "string", "pattern": CASE_ID_PATTERN,
               "description": "Unique id: a category prefix, '-', a number (PI-001, REFUND-0001)."},
        "category": {"type": "string"},
        "severity": {"enum": ["critical", "high", "medium"],
                     "description": "Gate thresholds are applied per severity."},
        "scenario": {"type": "string", "description": "What the case tests, for humans and the judge."},
        "input_payload": {"type": "string", "minLength": 1,
                          "description": "The user message the agent receives."},
        "expected_behavior": {"type": "string",
                              "description": "What a safe agent does; the LLM judge grades against it."},
        "allowed_tools": {**_TOOL_LIST, "description": "Tools the task legitimately needs (informational)."},
        "forbidden_tools": {**_TOOL_LIST,
                            "description": "Tools that FAIL the case if called; checked against the "
                                           "transcript and the mock-services audit log."},
        "required_tools": {**_TOOL_LIST, "description": "Tools that FAIL the case if NOT called."},
        "forbidden_output_patterns": {"type": "array", "items": {"type": "string"},
                                      "description": "Regexes that must not match the final answer."},
        "max_actions": {"type": "integer", "minimum": 1, "description": "Tool-call cap (default 10)."},
        "max_llm_calls": {"type": "integer", "minimum": 1,
                          "description": "LLM-call cap for this case (default MAX_LLM_CALLS)."},
        "fixtures": {"type": "array", "items": {"enum": _FIXTURES},
                     "description": "Adversarial content loaded into this run's mock world only."},
        "mock_responses": {"type": "object", "maxProperties": MAX_MOCK_RESPONSES,
                           "propertyNames": {"pattern": TOOL_NAME_PATTERN},
                           "description": "Generic tool name → the JSON mock-services answers it "
                                          "with (at most 64 KiB each)."},
        "tags": {"type": "array", "uniqueItems": True, "items": {"type": "string", "pattern": TAG_PATTERN},
                 "description": "Free labels for selection (`--tag smoke`); never graded."},
        "metadata": {"type": "object",
                     "description": "Free-form data for your own tooling; never graded or sent anywhere."},
        "probe": {"enum": ["judge"], "description": "Not run against the agent; tests the LLM judge."},
        "synthetic_transcript": {"type": "object",
                                 "description": "The transcript a judge probe shows the judge."},
    },
    "additionalProperties": False,
}

# Optional `library:` block beside `cases:`. Every existing reader does
# raw.get("cases"), so a header changes nothing for them.
LIBRARY_HEADER_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "required": ["schema_version"],
    "properties": {
        "schema_version": {"const": 1},
        "kind": {"enum": ["adversarial", "benign"]},
    },
    "additionalProperties": False,
}

_CASE_VALIDATOR = jsonschema.Draft202012Validator(CASE_SCHEMA)
_HEADER_VALIDATOR = jsonschema.Draft202012Validator(LIBRARY_HEADER_SCHEMA)


class LibraryError(ValueError):
    """The library file cannot be read as a library at all."""


@dataclass(frozen=True)
class Library:
    """A library as it was read: the exact bytes, so a batch can snapshot what it ran."""
    path: Path
    raw: bytes
    header: Any  # the `library:` block as written (None when absent); validate_header() checks it
    cases: List[Dict[str, Any]]

    @classmethod
    def read(cls, path: Path) -> "Library":
        try:
            raw = Path(path).read_bytes()
        except OSError as e:
            raise LibraryError(f"cannot read library {path}: {e.strerror or e}") from e
        return cls.parse(Path(path), raw)

    @classmethod
    def parse(cls, path: Path, raw: bytes) -> "Library":
        try:
            # Bytes, not text: PyYAML then honours a BOM, which Windows editors add.
            doc = yaml.safe_load(raw)
        except (yaml.YAMLError, UnicodeDecodeError) as e:
            raise LibraryError(f"{path.name} is not valid YAML: {e}") from e
        if isinstance(doc, list):
            return cls(path, raw, None, doc)
        if not isinstance(doc, dict):
            raise LibraryError(f"{path.name} must be a list of cases or a mapping with a "
                               f"`cases:` list, not {type(doc).__name__}")
        cases = doc.get("cases", [])
        if not isinstance(cases, list):
            raise LibraryError(f"{path.name}: `cases:` must be a list, not {type(cases).__name__}")
        return cls(path, raw, doc.get("library"), cases)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.raw).hexdigest()

    @property
    def kind(self) -> str:
        """adversarial | benign: a FAIL on a benign task is a false positive, not a detection."""
        declared = self.header.get("kind") if isinstance(self.header, dict) else None
        if declared in ("adversarial", "benign"):
            return declared
        return "benign" if "benign" in self.path.name.lower() else "adversarial"


def load_library(path: Path) -> List[Dict[str, Any]]:
    return Library.read(path).cases


def _schema_error(errors: Sequence[jsonschema.ValidationError]) -> str:
    best = jsonschema.exceptions.best_match(errors)
    where = best.json_path if best.absolute_path else ""
    return f"{where + ': ' if where else ''}{best.message}"


def validate_header(header: Any) -> List[str]:
    if header is None:
        return []
    errors = list(_HEADER_VALIDATOR.iter_errors(header))
    return [f"library header: {_schema_error(errors)}"] if errors else []


def validate(cases: List[Dict[str, Any]]) -> List[str]:
    """Schema + semantic validation. Returns error strings (empty = valid)."""
    errors: List[str] = []
    seen = set()
    for n, case in enumerate(cases, 1):
        if not isinstance(case, dict):
            errors.append(f"case #{n}: must be a mapping, not {type(case).__name__}")
            continue
        cid = case.get("id", f"case #{n}")
        schema_errors = list(_CASE_VALIDATOR.iter_errors(case))
        if schema_errors:
            errors.append(f"{cid}: {_schema_error(schema_errors)}")
            continue
        # The schema's `$` also matches before a trailing newline; the id becomes
        # a file name, so it must be exactly the pattern.
        if not re.fullmatch(CASE_ID_PATTERN, cid):
            errors.append(f"{cid!r}: id must match {CASE_ID_PATTERN} exactly")
            continue
        if cid in seen:
            errors.append(f"{cid}: duplicate id")
        seen.add(cid)
        overlap = set(case["allowed_tools"]) & set(case["forbidden_tools"])
        if overlap:
            errors.append(f"{cid}: tools both allowed and forbidden: {sorted(overlap)}")
        for pat in case["forbidden_output_patterns"]:
            try:
                re.compile(pat)
            except re.error as e:
                errors.append(f"{cid}: invalid regex {pat!r}: {e}")
        for tool, value in (case.get("mock_responses") or {}).items():
            size = len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
            if size > MAX_MOCK_RESPONSE_BYTES:
                errors.append(f"{cid}: mock_responses.{tool} is {size} bytes of JSON; "
                              f"mock-services accepts at most {MAX_MOCK_RESPONSE_BYTES}")
        if case.get("probe") == "judge" and "synthetic_transcript" not in case:
            errors.append(f"{cid}: judge probe needs synthetic_transcript")
    return errors


def validate_library(library: Library) -> List[str]:
    return validate_header(library.header) + validate(library.cases)


def non_bundled_tools(cases: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """{case id: tool names it uses that the bundled agent does not offer}."""
    out: Dict[str, List[str]] = {}
    for case in cases:
        named = {t for key in ("allowed_tools", "forbidden_tools", "required_tools")
                 for t in (case.get(key) or [])}
        extra = sorted(named - set(BUNDLED_TOOLS))
        if extra:
            out[case["id"]] = extra
    return out


def select_cases(cases: List[Dict[str, Any]], categories: Optional[List[str]] = None,
                 ids: Optional[List[str]] = None,
                 tags: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    out = [c for c in cases if not c.get("probe")]  # probes never run against the agent
    if categories:
        out = [c for c in out if c.get("category") in categories]
    if ids:
        out = [c for c in out if c["id"] in ids]
    if tags:
        out = [c for c in out if set(c.get("tags") or []) & set(tags)]
    return out


def export_case_schema(path: Path = CASE_SCHEMA_PATH) -> Path:
    """Write CASE_SCHEMA as JSON Schema for editors and other tools."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(CASE_SCHEMA, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


# ── Provenance ────────────────────────────────────────────────────────────────

def _library_ref(path: Path) -> str:
    """Repo-relative POSIX path when the library is in the repo, else absolute.
    An absolute path made a batch unreadable on any other machine."""
    resolved = Path(path).resolve()
    try:
        return resolved.relative_to(_ROOT.resolve()).as_posix()
    except ValueError:
        return str(resolved)


def _git_info() -> Optional[Dict[str, Any]]:
    """The commit the harness ran from and whether the working tree differed from
    it; None without git or outside a checkout. Untracked files count as dirty: a
    new variant prompt changes what runs without changing the commit."""
    def git(*args: str) -> Optional[str]:
        try:
            proc = subprocess.run(["git", *args], cwd=str(_ROOT), capture_output=True, text=True,
                                  timeout=15, encoding="utf-8", errors="replace")
        except (OSError, subprocess.SubprocessError):
            return None
        return proc.stdout if proc.returncode == 0 else None

    sha = git("rev-parse", "HEAD")
    if not sha or not sha.strip():
        return None
    status = git("status", "--porcelain")
    return {"sha": sha.strip(), "dirty": None if status is None else bool(status.strip())}


def _basename(recorded: Any) -> str:
    """File name of a path recorded on ANY OS: Path() does not split D:\\x\\y elsewhere."""
    return PureWindowsPath(str(recorded or "")).name


def resolve_library(manifest: Dict[str, Any], batch_dir: Path) -> Path:
    """
    The library a batch ran: its own snapshot first, then the recorded path
    (repo-relative, or absolute from this machine), then attacks/<basename>
    for a manifest written on another machine before snapshots existed.
    """
    snapshot = manifest.get("library_snapshot")
    if snapshot:
        candidate = (batch_dir / str(snapshot)).resolve()
        # The manifest is data: a snapshot path may not leave its batch.
        if candidate.parent == batch_dir.resolve() and candidate.is_file():
            return candidate
    recorded = manifest.get("library")
    if recorded:
        path = Path(str(recorded))
        for candidate in ((path,) if path.is_absolute() else (_ROOT / path,)):
            if candidate.is_file():
                return candidate
        fallback = _ROOT / "attacks" / _basename(recorded)
        if _basename(recorded) and fallback.is_file():
            return fallback
    raise FileNotFoundError(f"Library {recorded or snapshot!r} named by the manifest no longer exists.")


# ── Batch execution ───────────────────────────────────────────────────────────

# Consecutive rate-limit failures that mean "the quota is gone, stop trying".
_QUOTA_BREAKER = int(os.getenv("QUOTA_BREAKER", "3"))
# The same, for the other failures that will not go away by themselves.
_ERROR_BREAKER = int(os.getenv("ERROR_BREAKER", "3"))
# How often the main thread wakes while cases run, to check for a signal (the
# handler only records it; see _signals_interrupt). A blocking wait would also
# keep Ctrl-C out on Windows, where lock waits are not interrupted by signals.
_POLL_SECONDS = 0.5
# After Ctrl-C, how long to wait for in-flight cases whose containers were
# just removed, so their transcripts are recorded rather than lost.
_DRAIN_SECONDS = 30.0


def _is_quota_error(transcript: Dict[str, Any]) -> bool:
    """True when a case failed because the LLM provider refused on rate/quota."""
    if transcript.get("status") == "completed":
        return False
    err = str(transcript.get("error") or "").lower()
    return "ratelimit" in err or "rate_limit" in err or "429" in err


# Error classes that fail every remaining case the same way, read from the
# error text on the host (the agent reports `Type: message` then a traceback).
# Patterns are the SDK's exact phrasing, not bare numbers, because the
# traceback carries line numbers.
_ERROR_CLASSES: Tuple[Tuple[str, "re.Pattern[str]", str], ...] = (
    ("auth", re.compile(r"Error code: 401\b|AuthenticationError|invalid_api_key|401 Unauthorized"),
     "The LLM provider rejected the API key (HTTP 401). Check LLM_API_KEY in .env - llm-proxy "
     "injects it - and recreate llm-proxy."),
    ("not_found", re.compile(r"Error code: 404\b|NotFoundError|model_not_found"),
     "The provider does not know the model or the endpoint (HTTP 404). Check AGENT_MODEL and "
     "AGENT_API_BASE (and LLM_UPSTREAM_PATH_PREFIX)."),
    ("forbidden", re.compile(r"Error code: 403\b|PermissionDeniedError|egress denied"),
     "The request was refused (HTTP 403): by llm-proxy when the path is not on its allowlist "
     "(AGENT_API_BASE, LLM_ALLOWED_ENDPOINTS), or by the provider."),
    ("connection", re.compile(r"APIConnectionError|APITimeoutError|Connection error|ConnectError|"
                              r"Connection refused|Name or service not known|getaddrinfo failed|"
                              r"Temporary failure in name resolution|SSLError|SSL: |"
                              r"CERTIFICATE_VERIFY_FAILED|Error code: 50[24]\b"),
     "The LLM endpoint could not be reached (connection, TLS or gateway error). Check "
     "LLM_UPSTREAM_HOST, that llm-proxy is healthy, and any intercepting proxy's CA "
     "(LLM_PROXY_EXTRA_CA_FILE)."),
)
_ERROR_HINTS = {name: hint for name, _, hint in _ERROR_CLASSES}


def classify_error(transcript: Dict[str, Any]) -> Optional[str]:
    """quota | auth | not_found | forbidden | connection, or None (completed or unrecognised)."""
    if transcript.get("status") == "completed":
        return None
    if _is_quota_error(transcript):
        return "quota"
    err = str(transcript.get("error") or "")
    for name, pattern, _ in _ERROR_CLASSES:
        if pattern.search(err):
            return name
    return None


class _Breaker:
    """
    Trips on N consecutive failed cases of one error class. Once the quota is
    gone, or the key is wrong, every remaining case fails identically: that
    wastes the run AND reads as a perfect detection rate downstream (the judge
    fails a failed case closed). Quota keeps its own threshold, QUOTA_BREAKER.
    """

    def __init__(self) -> None:
        self.error_class: Optional[str] = None
        self.count = 0

    def record(self, transcript: Dict[str, Any]) -> Optional[str]:
        """The error class that just tripped the breaker, or None."""
        cls = classify_error(transcript)
        if cls is None:
            self.error_class, self.count = None, 0
            return None
        if cls == self.error_class:
            self.count += 1
        else:
            self.error_class, self.count = cls, 1
        limit = _QUOTA_BREAKER if cls == "quota" else _ERROR_BREAKER
        return cls if self.count >= limit else None


class BatchInterrupted(KeyboardInterrupt):
    """Ctrl-C/SIGTERM stopped a batch. Its manifest was written first, so the
    finished cases survive for --resume; still a KeyboardInterrupt, so a caller
    running batches in a loop stops too."""

    def __init__(self, manifest_path: Path) -> None:
        super().__init__(f"batch interrupted; manifest: {manifest_path}")
        self.manifest_path = manifest_path


@dataclass
class _Outcome:
    entries: List[Dict[str, Any]] = field(default_factory=list)
    stopped: Optional[Dict[str, Any]] = None  # why the batch ended early, if it did


def _agent_model() -> Optional[str]:
    return (os.getenv("AGENT_MODEL") or "").strip() or None


def _print_warnings(variant: str, image: Optional[str]) -> None:
    """The harness's non-blocking warnings (a prompt without the canary, an
    unset AGENT_MAX_TOKENS), shown before quota is spent rather than discovered
    in a report. Optional: an older sandbox/run_test.py has neither function."""
    import run_test  # already imported above; the module, for its optional helpers
    found: List[Optional[str]] = []
    try:
        canary = getattr(run_test, "canary_warning", None)
        if canary:
            found.append(canary(variant, image=image))
        general = getattr(run_test, "preflight_warnings", None)
        if general:
            found.extend(general())
    except Exception as e:  # pylint: disable=broad-except - a warning must never block a run
        found.append(f"could not check the harness warnings: {type(e).__name__}: {e}")
    for warning in filter(None, found):
        console.print(f"[yellow]⚠ {warning}[/yellow]")


def _new_batch_id() -> str:
    # Labels this execution's containers. Unique per run AND per resume, so
    # interrupting one loader can never remove another loader's containers.
    return f"{time.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:12]}"


def _write_json(path: Path, data: Any) -> None:
    """Write via a temp file and rename, so a kill mid-write leaves the old file
    or the new one, never half of one."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    for attempt in range(5):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            # Windows refuses to replace a file another process has open (the
            # results browser, an antivirus scan); it is released within moments.
            if attempt == 4:
                raise
            time.sleep(0.1 * (attempt + 1))


def _harness_error(case: Dict[str, Any], variant: str, error: BaseException) -> Dict[str, Any]:
    return {"test_id": case["id"], "variant": variant, "status": "harness_error",
            "error": f"{type(error).__name__}: {error}", "tool_calls": [], "steps": [],
            "service_audit": None, "output": ""}


def _entry(case_id: str, transcript: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": case_id,
        "status": transcript.get("status"),
        # Relative to the batch folder, so the folder can be moved or downloaded.
        "transcript": f"{case_id}.json",
        # Recorded per case so a resumed batch can never hide that some of its
        # cases came from a different model or image.
        "agent_model": transcript.get("model"),
        "agent_image_id": transcript.get("agent_image_id"),
        "elapsed_seconds": transcript.get("elapsed_seconds"),
    }


def _run_and_persist(case: Dict[str, Any], variant: str, batch_dir: Path,
                     stopping: Callable[[], bool], image: Optional[str],
                     batch_id: str) -> Optional[Dict[str, Any]]:
    """
    One case, in a worker thread. Returns None if the batch stopped before it
    started. The transcript is written HERE, not by the main thread: a case
    that finishes while the main thread is handling Ctrl-C would otherwise be
    lost and cost its quota again on --resume.
    """
    if stopping():
        return None
    try:
        transcript = run_case(case, variant, batch_id=batch_id, image=image)
    except Exception as e:  # pylint: disable=broad-except - never lose a case
        transcript = _harness_error(case, variant, e)
    _write_json(batch_dir / f"{case['id']}.json", transcript)
    return transcript


@contextmanager
def _signals_interrupt(state: Dict[str, Any]) -> Iterator[None]:
    """
    Record SIGINT and SIGTERM (and Ctrl-Break on Windows) in `state["signal"]`
    for the batch loop to act on. Without this, SIGTERM - CI cancelling a job,
    `timeout`, a closed console - exits without cleanup and orphans the
    `docker run` children, which keep spending quota through llm-proxy.

    The handler only records; it does not raise. A KeyboardInterrupt raised
    from a handler lands at an arbitrary point in the main thread, including
    inside concurrent.futures.wait() while it holds a Future's lock: the worker
    finishing that case then blocks for ever, and so does the interpreter's
    exit, which joins it. The batch loop polls anyway (see _POLL_SECONDS), so
    it stops at a safe point within half a second. Repeats are ignored.

    Signal handlers can only be set from the main thread; elsewhere this does
    nothing, and the caller gets no signals to handle anyway.
    """
    if threading.current_thread() is not threading.main_thread():
        yield
        return

    def handler(signum: int, _frame: Any) -> None:
        # A plain dict store: no lock, so it cannot deadlock whatever it interrupts.
        if "signal" not in state:
            try:
                state["signal"] = signal.Signals(signum).name
            except ValueError:
                state["signal"] = str(signum)

    previous: Dict[int, Any] = {}
    # getattr: SIGTERM cannot be delivered to a Windows process from outside
    # (TerminateProcess skips handlers), and SIGBREAK exists only there.
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
    cases: List[Dict[str, Any]],
    variant: str,
    batch_dir: Path,
    workers: int,
    on_result: Optional[Callable[[Dict[str, Any], Dict[str, Any], Path], None]],
    description: str,
    *,
    image: Optional[str] = None,
    batch_id: Optional[str] = None,
    checkpoint: Optional[Callable[[List[Dict[str, Any]], Optional[Dict[str, Any]]], None]] = None,
) -> _Outcome:
    """
    Run `cases` in parallel sandbox containers, writing one transcript per case
    into `batch_dir`. Stops early when the circuit breaker trips or on
    Ctrl-C/SIGTERM. `checkpoint(entries, stopped)` is called after every case
    and once at the end, so the manifest on disk is never more than one case
    behind. Returns the manifest entries sorted by id.
    """
    batch_id = batch_id or _new_batch_id()
    by_id = {case["id"]: case for case in cases}
    recorded: Dict[str, Dict[str, Any]] = {}
    stopped: Dict[str, Any] = {}
    signals: Dict[str, Any] = {}
    stop = threading.Event()
    breaker = _Breaker()

    # A live spinner writes a frame per refresh; piped to a file or a CI log that
    # is thousands of useless lines, so animate only on a real terminal.
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(),
                  TextColumn("{task.completed}/{task.total}"), TimeElapsedColumn(),
                  console=console, transient=False,
                  # console.is_terminal is not enough: FORCE_COLOR (set by many
                  # CI runners and agent harnesses) makes rich claim a terminal
                  # even when stdout is a file.
                  disable=not sys.stdout.isatty()) as progress, _signals_interrupt(signals):
        task = progress.add_task(description, total=len(cases))

        def entries() -> List[Dict[str, Any]]:
            return sorted(recorded.values(), key=lambda e: e["id"])

        def record(fut: Future, live: bool) -> Optional[Dict[str, Any]]:
            case = futures[fut]
            if fut.cancelled():
                return None
            try:
                transcript = fut.result()
            except Exception as e:  # pylint: disable=broad-except - e.g. the disk filled up
                transcript = _harness_error(case, variant, e)
                try:
                    _write_json(batch_dir / f"{case['id']}.json", transcript)
                except OSError as write_error:
                    progress.console.print(f"[red]✗ could not write {case['id']}.json: {write_error}[/red]")
            if transcript is None or case["id"] in recorded:
                return None  # never started, or already recorded
            recorded[case["id"]] = _entry(case["id"], transcript)
            ok = transcript.get("status") == "completed"
            tools = sorted({str(t.get("tool")) for t in (transcript.get("tool_calls") or [])
                            if isinstance(t, dict) and t.get("tool")})
            progress.console.print(
                f"  {'[green]✓[/green]' if ok else '[red]✗[/red]'} {case['id']:<7} "
                f"{str(transcript.get('status', '?')):<16} tools={tools}"
                + ("" if ok else f"  [red]{str(transcript.get('error', ''))[:120]}[/red]"))
            progress.advance(task)
            if live and on_result:
                on_result(case, transcript, batch_dir / f"{case['id']}.json")
            if checkpoint:
                checkpoint(entries(), None)
            return transcript

        def in_case_order(done: Any) -> List[Future]:
            order = {cid: n for n, cid in enumerate(by_id)}
            return sorted(done, key=lambda f: order[futures[f]["id"]])

        def interrupted() -> None:
            # Where a signal turns into the interrupt path: between waits, when
            # this thread holds no lock.
            if signals.get("signal"):
                raise KeyboardInterrupt(signals["signal"])

        def drain(timeout: Optional[float], interruptible: bool = False) -> None:
            # Futures that were running when the batch stopped: record whatever
            # finishes (their transcripts are on disk either way). Cancelled ones
            # are left out: wait() never reports a future cancelled straight off
            # the queue as done, so it would poll for ever.
            remaining = {f for f in futures if not f.cancelled()
                         and (not f.done() or futures[f]["id"] not in recorded)}
            deadline = None if timeout is None else time.monotonic() + timeout
            while remaining:
                if interruptible:
                    interrupted()
                left = _POLL_SECONDS if deadline is None else min(_POLL_SECONDS, deadline - time.monotonic())
                if left <= 0:
                    break
                done, remaining = wait(remaining, timeout=left)
                for fut in in_case_order(done):
                    record(fut, live=False)

        pool = ThreadPoolExecutor(max_workers=max(1, workers), thread_name_prefix="creuset-case")
        futures: Dict[Future, Dict[str, Any]] = {}
        try:
            try:
                # Inside the try: a Ctrl-C between two submits must still cancel
                # what was queued, or the pool would run it all before exiting.
                # A worker also reads the recorded signal itself, so a case
                # cannot start between the signal and the main thread's next poll.
                def stopping() -> bool:
                    return stop.is_set() or bool(signals.get("signal"))

                for case in cases:
                    futures[pool.submit(_run_and_persist, case, variant, batch_dir, stopping, image,
                                        batch_id)] = case
                pending = set(futures)
                while pending and not stopped:
                    interrupted()
                    done, pending = wait(pending, timeout=_POLL_SECONDS, return_when=FIRST_COMPLETED)
                    for fut in in_case_order(done):
                        transcript = record(fut, live=True)
                        tripped = breaker.record(transcript) if transcript is not None else None
                        if tripped and not stopped:
                            stopped.update({"reason": "circuit_breaker", "error_class": tripped,
                                            "consecutive": breaker.count})
                if stopped:
                    stop.set()
                    pool.shutdown(wait=False, cancel_futures=True)
                    _print_breaker(progress.console, stopped, len(cases) - len(recorded), batch_dir)
                    drain(timeout=None, interruptible=True)  # in-flight cases finish
            except KeyboardInterrupt:
                stop.set()
                pool.shutdown(wait=False, cancel_futures=True)
                stopped.clear()
                stopped.update({"reason": "interrupted", "signal": signals.get("signal") or "SIGINT"})
                signals.setdefault("signal", stopped["signal"])  # ignore repeats from here on
                progress.console.print(f"[bold yellow]⏹ {stopped['signal']}: stopping the batch.[/bold yellow] "
                                       "Queued cases will not start; removing this batch's containers.")
                try:
                    removed = remove_batch_containers(batch_id)
                    stopped["containers_removed"] = removed
                except Exception as e:  # pylint: disable=broad-except - cleanup must not mask the stop
                    progress.console.print(f"[red]✗ could not remove the batch's containers: {e}[/red]")
                drain(timeout=_DRAIN_SECONDS)
        finally:
            stop.set()
            pool.shutdown(wait=False, cancel_futures=True)
            if checkpoint:
                checkpoint(entries(), stopped or None)

    return _Outcome(entries=entries(), stopped=stopped or None)


def _print_breaker(out: Console, stopped: Dict[str, Any], not_run: int, batch_dir: Path) -> None:
    cls = stopped["error_class"]
    if cls == "quota":
        out.print(
            f"[bold red]⛔ Aborting batch: {stopped['consecutive']} consecutive "
            f"provider rate-limit failures.[/bold red] The remaining "
            f"{not_run} case(s) were not run - results from this "
            f"batch are incomplete, not a measurement. Finish it with "
            f"[bold]--resume {batch_dir}[/bold] once the quota resets; every case "
            f"that did complete is kept.")
        return
    out.print(
        f"[bold red]⛔ Aborting batch: {stopped['consecutive']} consecutive cases failed the same "
        f"way ({cls}).[/bold red] {_ERROR_HINTS.get(cls, '')} The remaining {not_run} case(s) "
        f"were not run - results from this batch are incomplete, not a measurement. Fix the "
        f"cause, then finish it with [bold]--resume {batch_dir}[/bold]; every case that did "
        f"complete is kept.")


def _new_batch_dir(runs_dir: Path, name: str) -> Path:
    # Exclusive: two runs started in the same second used to share one folder
    # and overwrite each other's transcripts.
    runs_dir.mkdir(parents=True, exist_ok=True)
    for n in range(1, 1000):
        candidate = runs_dir / (name if n == 1 else f"{name}-{n}")
        try:
            candidate.mkdir()
            return candidate
        except FileExistsError:
            continue
    raise RuntimeError(f"Could not create a batch folder for {name} in {runs_dir}.")


def _complete(entries: List[Dict[str, Any]], case_count: int) -> bool:
    return len(entries) == case_count


def run_suite(
    cases: List[Dict[str, Any]],
    variant: str,
    library: Path,
    workers: int = 1,
    categories: Optional[List[str]] = None,
    on_result: Optional[Callable[[Dict[str, Any], Dict[str, Any], Path], None]] = None,
    label: str = "",
    selected_ids: Optional[List[str]] = None,
    *,
    tags: Optional[List[str]] = None,
    image: Optional[str] = None,
    runs_dir: Optional[Path] = None,
    source: Optional[Library] = None,
) -> Path:
    """
    Run `cases` in parallel sandbox containers, save transcripts + manifest.
    `on_result(case, transcript, path)` is called as each case finishes (the gate
    uses it to start judging while other cases are still running).
    `source` is the Library the cases came from (read from `library` if not
    given); its exact bytes are snapshotted into the batch.
    Returns the manifest path. Raises BatchInterrupted (after writing the
    manifest) on Ctrl-C/SIGTERM, and RuntimeError if the image does not exist.
    """
    image_ref, image_id = resolve_image(image)
    lib = source or Library.read(library)
    git = _git_info()  # before the batch folder exists: it may sit inside the checkout

    stamp = time.strftime("%Y%m%d-%H%M%S")
    batch_dir = _new_batch_dir((runs_dir or RUNS_DIR).resolve(),
                               f"{stamp}_{variant}_{Path(library).stem}{('_' + label) if label else ''}")
    (batch_dir / LIBRARY_SNAPSHOT).write_bytes(lib.raw)
    batch_id = _new_batch_id()

    manifest: Dict[str, Any] = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "ts": int(time.time()),
        "variant": variant,
        "library": _library_ref(library),
        "library_sha256": lib.sha256,
        "library_snapshot": LIBRARY_SNAPSHOT,
        "kind": lib.kind,
        "categories": categories,
        "selected_ids": selected_ids,  # ad-hoc subset: coverage applies to these only
        "tags": tags,
        "agent_model": _agent_model(),
        "agent_image": image_ref,
        "agent_image_id": image_id,
        "git": git,
        "batch_id": batch_id,
        "case_count": len(cases),
        # False until every case has run; stays False when the batch stopped
        # early - the missing cases are unrun, not passed or failed.
        "complete": False,
        "stopped": None,
        "cases": [],
    }
    manifest_path = batch_dir / "manifest.json"

    def checkpoint(entries: List[Dict[str, Any]], stopped: Optional[Dict[str, Any]]) -> None:
        manifest.update({"ts": int(time.time()), "cases": entries, "stopped": stopped,
                         "complete": _complete(entries, len(cases))})
        _write_json(manifest_path, manifest)

    # Written before the first case starts: a batch killed outright (SIGKILL, a
    # power cut) still leaves something --resume can pick up.
    checkpoint([], None)
    outcome = _execute_cases(cases, variant, batch_dir, workers, on_result,
                             f"[cyan]{variant}[/cyan] × {Path(library).stem}",
                             image=image_ref, batch_id=batch_id, checkpoint=checkpoint)
    if outcome.stopped and outcome.stopped.get("reason") == "interrupted":
        raise BatchInterrupted(manifest_path)
    return manifest_path


def _needs_rerun(case_id: str, entry: Optional[Dict[str, Any]], batch_dir: Path,
                 redo_empty: bool, redo_ids: Optional[List[str]]) -> Optional[str]:
    """Why this case has to run again, or None to keep the transcript it already has."""
    if redo_ids and case_id in redo_ids:
        return "forced with --redo"
    if entry is None:
        return "never ran (the batch stopped before reaching it)"
    if entry.get("status") != "completed":
        return f"previous status was '{entry.get('status')}'"
    # The manifest says completed, but a transcript the judge cannot read is
    # scored as missing, i.e. FAIL - so it has to exist and parse.
    path = batch_dir / f"{case_id}.json"
    if not path.exists():
        return "transcript file is missing"
    try:
        transcript = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "transcript file is unreadable"
    if not isinstance(transcript, dict):
        return "transcript file is unreadable"
    if redo_empty and not str(transcript.get("output") or "").strip():
        return "completed with an empty final answer"
    return None


def _reconcile_with_disk(batch_dir: Path, in_scope: List[Dict[str, Any]],
                         prior: Dict[str, Dict[str, Any]]) -> List[str]:
    """
    Rebuild the manifest's case entries from the transcripts actually on disk.

    The manifest is a derived index; transcripts are written as each case
    finishes. So the two disagree whenever a batch was killed in between -
    Ctrl-C, a closed pipe, a crashed machine - in two ways, both of which cost
    quota if believed:

      • a finished case the manifest never lists, which --resume would run again;
      • an entry whose cached status is staler than its transcript, e.g. still
        'error' after a later attempt succeeded, which --resume would also run
        again.

    The transcript file is the ground truth, so every entry is refreshed from it
    (which also rewrites legacy absolute paths as batch-relative ones).
    Mutates `prior` and returns the ids whose status changed.
    """
    changed: List[str] = []
    for case in in_scope:
        cid = case["id"]
        path = batch_dir / f"{cid}.json"
        if not path.exists():
            continue
        try:
            transcript = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue  # unreadable: leave it to be re-run
        if not isinstance(transcript, dict):
            continue
        entry = _entry(cid, transcript)
        old = prior.get(cid)
        if old is None or old.get("status") != entry["status"]:
            changed.append(cid)
        prior[cid] = entry
    return changed


def _check_snapshot(manifest: Dict[str, Any], library: Path) -> Optional[str]:
    """Why the library about to be resumed is not the one the batch ran, or None."""
    expected = manifest.get("library_sha256")
    if not expected:
        return None  # a batch from before library hashes: nothing to compare
    actual = hashlib.sha256(library.read_bytes()).hexdigest()
    if actual == expected:
        return None
    return (f"{library} does not match the library this batch ran (sha256 {expected[:12]}…, now "
            f"{actual[:12]}…). Resuming would mix two versions of its cases in one batch.")


def resume_suite(
    batch_dir: Path,
    workers: int = 1,
    redo_empty: bool = False,
    redo_ids: Optional[List[str]] = None,
    allow_model_change: bool = False,
    on_result: Optional[Callable[[Dict[str, Any], Dict[str, Any], Path], None]] = None,
    *,
    image: Optional[str] = None,
    allow_image_change: bool = False,
) -> Path:
    """
    Finish a batch that stopped early, re-running only the cases that need it.

    A run killed by the provider's daily quota used to be worthless: the whole
    batch was discarded and the next attempt restarted from zero, which is why
    several days of quota produced no complete measurement. Cases are independent
    - each runs in its own container against a freshly initialised world - so
    completing a batch case by case is sound, PROVIDED every transcript in it came
    from the same agent model, the same agent image and the same library. Those
    provisos are enforced rather than trusted: model and image are checked against
    the manifest and then recorded per case, and the library is the batch's own
    snapshot.

    Returns the updated manifest path. Raises BatchInterrupted on Ctrl-C/SIGTERM.
    """
    manifest_path = batch_dir / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"No manifest.json in {batch_dir} - nothing to resume.")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError(f"{manifest_path} is not a batch manifest.")

    variant = manifest.get("variant")
    library = resolve_library(manifest, batch_dir)
    problem = _check_snapshot(manifest, library)
    if problem:
        raise ValueError(problem)

    all_cases = Library.read(library).cases
    in_scope = select_cases(all_cases, manifest.get("categories"), manifest.get("selected_ids"),
                            manifest.get("tags"))
    scope_ids = {c["id"] for c in in_scope}
    prior = {e["id"]: e for e in manifest.get("cases") or [] if isinstance(e, dict) and "id" in e}
    reconciled = _reconcile_with_disk(batch_dir, in_scope, prior)
    if reconciled:
        console.print(f"[dim]Reconciled {len(reconciled)} case(s) against the transcripts on disk "
                      f"(the manifest was stale or never written): {reconciled}[/dim]")

    todo: List[Dict[str, Any]] = []
    reasons: Dict[str, str] = {}
    for case in in_scope:
        why = _needs_rerun(case["id"], prior.get(case["id"]), batch_dir, redo_empty, redo_ids)
        if why:
            todo.append(case)
            reasons[case["id"]] = why

    # A --redo id outside this batch's scope would otherwise do nothing at all,
    # silently, and look like the re-run happened.
    unknown = sorted(set(redo_ids or []) - scope_ids)
    if unknown:
        console.print(f"[yellow]⚠ --redo named {unknown}, which this batch does not cover "
                      f"(variant {variant}, {library.name}). Ignored.[/yellow]")

    console.print(f"[bold]Resuming[/bold] {batch_dir.name} - variant [cyan]{variant}[/cyan], "
                  f"{len(scope_ids & set(prior))}/{len(in_scope)} case(s) already present.")

    def write(entries: List[Dict[str, Any]], stopped: Optional[Dict[str, Any]],
              ran: Optional[Dict[str, Any]] = None) -> None:
        merged = {**prior, **{e["id"]: e for e in entries}}
        kept = sorted((e for e in merged.values() if e["id"] in scope_ids), key=lambda e: e["id"])
        manifest.update({"ts": int(time.time()), "case_count": len(in_scope),
                         "complete": _complete(kept, len(in_scope)), "stopped": stopped, "cases": kept})
        manifest.update(ran or {})  # the model and image, only when something ran under them
        _write_json(manifest_path, manifest)

    if not todo:
        # Idempotent and offline: a finished batch needs no Docker, no image and
        # no quota, only its manifest brought in line with what is on disk.
        console.print("[green]✓ Nothing to re-run; this batch is already complete.[/green]")
        if reconciled or not manifest.get("complete") or manifest.get("stopped"):
            write([], None)
        return manifest_path

    image_ref, image_id = resolve_image(image or manifest.get("agent_image"))
    problem = validate_variant(variant, image=image_ref)
    if problem:
        raise ValueError(f"Manifest names an unusable variant: {problem}")

    # Mixing models inside one batch makes its results incomparable, and it is
    # invisible once the numbers reach a table. Refuse by default.
    current_model = _agent_model()
    previous_model = manifest.get("agent_model")
    if previous_model and current_model != previous_model and not allow_model_change:
        raise ValueError(
            f"This batch ran with AGENT_MODEL={previous_model}, but AGENT_MODEL is now "
            f"{current_model}. Resuming would mix two models inside one batch, which makes "
            f"its results incomparable. Set AGENT_MODEL back, or pass --allow-model-change "
            f"if you genuinely intend a mixed batch.")
    # The same for the build: a rebuilt creuset-agent:latest keeps its name but
    # can carry a different prompt, agent loop or LangChain.
    previous_image = manifest.get("agent_image_id")
    if previous_image and image_id != previous_image and not allow_image_change:
        raise ValueError(
            f"This batch ran agent image {previous_image[:19]}..., but {image_ref} is now "
            f"{image_id[:19]}.... Resuming would mix two agent builds inside one batch, which "
            f"makes its results incomparable. Run the original image again (--image), or pass "
            f"--allow-image-change if you genuinely intend a mixed batch.")

    for cid in sorted(reasons):
        console.print(f"  [yellow]↻[/yellow] {cid:<7} {reasons[cid]}")
    _print_warnings(variant, image_ref)
    problems = preflight(image_ref)
    if problems:
        for problem in problems:
            console.print(f"[red]✗[/red] {problem}")
        raise RuntimeError("Preflight failed; nothing was run.")

    batch_id = _new_batch_id()
    manifest.setdefault("resumes", []).append({
        "ts": int(time.time()),
        "agent_model": current_model,
        "agent_image_id": image_id,
        "batch_id": batch_id,
        "git": _git_info(),
        "reran": sorted(reasons),
        "reasons": reasons,
    })
    ran = {"agent_model": current_model, "agent_image": image_ref, "agent_image_id": image_id}
    outcome = _execute_cases(todo, variant, batch_dir, workers, on_result,
                             f"[cyan]{variant}[/cyan] × {library.stem} [dim](resume)[/dim]",
                             image=image_ref, batch_id=batch_id,
                             checkpoint=lambda entries, stopped: write(entries, stopped, ran))
    if outcome.stopped and outcome.stopped.get("reason") == "interrupted":
        raise BatchInterrupted(manifest_path)
    return manifest_path


def batch_exit_code(manifest: Dict[str, Any]) -> int:
    """0 when the batch is complete and every case completed, else 3."""
    entries = [e for e in manifest.get("cases") or [] if isinstance(e, dict)]
    if not entries or not manifest.get("complete") or manifest.get("stopped"):
        return 3
    if len(entries) < int(manifest.get("case_count") or 0):
        return 3
    return 0 if all(e.get("status") == "completed" for e in entries) else 3


def _summarise(manifest_path: Path) -> int:
    """Print a batch's per-case table, then the manifest path last for scripting.
    Returns the exit code the batch deserves."""
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    table = Table(title=f"Batch — variant: {manifest.get('variant')}", show_lines=False)
    table.add_column("ID", style="bold")
    table.add_column("Status")
    table.add_column("Elapsed")
    for e in manifest["cases"]:
        color = "green" if e["status"] == "completed" else "red"
        table.add_row(e["id"], f"[{color}]{e['status']}[/{color}]", f"{e.get('elapsed_seconds') or '?'}s")
    console.print(table)

    # One batch must mean one model and one build, or its numbers cannot be
    # compared. A resumed batch records both per case, so say plainly when they disagree.
    for what, key in (("agent models", "agent_model"), ("agent images", "agent_image_id")):
        seen = sorted({e.get(key) for e in manifest["cases"] if e.get(key)})
        if len(seen) > 1:
            console.print(f"[bold red]⚠ This batch mixes {what} {seen} — its cases are not "
                          f"comparable with each other.[/bold red]")
    failed = [e["id"] for e in manifest["cases"] if e.get("status") != "completed"]
    if failed:
        console.print(f"[yellow]⚠ {len(failed)} case(s) did not complete: {failed}. They are harness "
                      f"failures, not results; re-run them with --resume {manifest_path.parent}[/yellow]")
    if not manifest.get("complete", True):
        done = len(manifest["cases"])
        stopped = manifest.get("stopped") or {}
        why = {"interrupted": f" (stopped by {stopped.get('signal')})",
               "circuit_breaker": f" (circuit breaker: {stopped.get('error_class')})"}.get(stopped.get("reason"), "")
        console.print(f"[yellow]⚠ Incomplete{why}: {done}/{manifest.get('case_count')} case(s) ran. "
                      f"Finish it with --resume {manifest_path.parent}[/yellow]")
    console.print(f"[bold]Manifest:[/bold] {manifest_path}")
    # Always print the manifest path last on stdout for scripting.
    print(manifest_path)
    return batch_exit_code(manifest)


def _write_manifest_out(target: Optional[Path], manifest_path: Path) -> None:
    """--manifest-out: the path as one line, so a script need not parse stdout."""
    if not target:
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    tmp.write_text(f"{manifest_path}\n", encoding="utf-8")
    os.replace(tmp, target)


def _split_ids(raw: Optional[str]) -> Optional[List[str]]:
    if not raw:
        return None
    return [c.strip() for c in raw.split(",") if c.strip()] or None


def _fail(message: str, code: int = 2) -> typer.Exit:
    console.print(f"[red]✗ {message}[/red]")
    return typer.Exit(code=code)


# ── CLI ───────────────────────────────────────────────────────────────────────

@app.command()
def main(
    library: Path = typer.Option(DEFAULT_LIBRARY, help="Path to the test library YAML."),
    variant: str = typer.Option("hardened", help="Agent variant: naive | hardened | broken"),
    category: Optional[List[str]] = typer.Option(None, help="Only these categories (repeatable)."),
    cases: Optional[str] = typer.Option(None, help="Comma-separated case IDs to run."),
    tag: Optional[List[str]] = typer.Option(None, "--tag", metavar="TAG",
                                            help="Only cases carrying this tag (repeatable: any of them)."),
    image: Optional[str] = typer.Option(None, "--image", metavar="REF",
                                        help="Agent image to test (default: AGENT_IMAGE, else "
                                             "creuset-agent:latest)."),
    workers: int = typer.Option(int(os.getenv("GATE_WORKERS", "1")), help="Parallel sandbox containers."),
    batch_root: Optional[Path] = typer.Option(None, "--batch-dir", metavar="DIR",
                                              help="Parent folder for batch folders (default: logs/runs)."),
    manifest_out: Optional[Path] = typer.Option(None, "--manifest-out", metavar="PATH",
                                                help="Also write the manifest path to this file, as one line."),
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
                                            help="With --resume, allow finishing a batch with a different "
                                                 "agent image. Makes the batch internally incomparable."),
    export_schema: bool = typer.Option(False, "--export-schema",
                                       help="Write schemas/case.v1.json from the case schema and exit."),
) -> None:
    """Validate the library and batch-run its cases through the sandbox."""
    if export_schema:
        console.print(f"[green]✓[/green] Wrote {export_case_schema()}")
        raise typer.Exit(code=0)
    if manifest_out:
        # A stale path from an earlier run must not be mistaken for this one's.
        try:
            manifest_out.unlink(missing_ok=True)
        except OSError as e:
            raise _fail(f"--manifest-out {manifest_out}: {e}")

    if resume:
        # The variant, library and case selection all come from the batch being
        # resumed; passing them again could only contradict it.
        batch_dir = resume.parent if resume.name == "manifest.json" else resume
        try:
            manifest_path = resume_suite(
                batch_dir, workers, redo_empty, _split_ids(redo), allow_model_change,
                image=image, allow_image_change=allow_image_change,
            )
        except BatchInterrupted as e:
            manifest_path = e.manifest_path
        except (FileNotFoundError, ValueError, RuntimeError, json.JSONDecodeError) as e:
            raise _fail(str(e))
        _write_manifest_out(manifest_out, manifest_path)
        raise typer.Exit(code=_summarise(manifest_path))

    try:
        lib = Library.read(library)
    except LibraryError as e:
        raise _fail(str(e), code=1 if dry_run else 2)
    all_cases = lib.cases
    console.print(f"[bold]Loaded[/bold] {len(all_cases)} cases from [cyan]{library}[/cyan] "
                  f"[dim]({lib.kind})[/dim]")

    errors = validate_library(lib)
    if errors:
        console.print("[red]Library validation errors:[/red]")
        for e in errors:
            console.print(f"  ✗ {e}")
        raise typer.Exit(code=1 if dry_run else 2)
    probes = [c["id"] for c in all_cases if c.get("probe")]
    console.print("[green]✓ All cases valid.[/green]"
                  + (f" [dim](judge probes, not run against the agent: {probes})[/dim]" if probes else ""))
    if dry_run:
        extra = non_bundled_tools(all_cases)
        if extra:
            console.print(f"[yellow]⚠ {len(extra)} case(s) name tools the bundled agent does not offer "
                          f"(fine for another agent image; a typo otherwise): {extra}[/yellow]")
        raise typer.Exit(code=0)

    ids = _split_ids(cases)
    known = {c["id"] for c in all_cases}
    unknown = [i for i in ids or [] if i not in known]
    if unknown:
        # A typo in a CI subset used to run nothing and exit 0.
        raise _fail(f"--cases names id(s) not in {library.name}: {unknown}")
    selected = select_cases(all_cases, category, ids, tag)
    if not selected:
        named_probes = [i for i in ids or [] if i in probes]
        raise _fail("No cases selected" + (f" ({named_probes} are judge probes, never run against "
                                           f"the agent)" if named_probes else "")
                    + ". Check --cases, --category and --tag.")
    if ids:
        dropped = sorted(set(ids) - {c["id"] for c in selected})
        if dropped:
            console.print(f"[yellow]⚠ Named but not selected by the other filters: {dropped}[/yellow]")
    for t in tag or []:
        if not any(t in (c.get("tags") or []) for c in all_cases):
            console.print(f"[yellow]⚠ No case in {library.name} carries tag {t!r}.[/yellow]")

    problems = preflight(image)
    if problems:
        for p in problems:
            console.print(f"[red]✗[/red] {p}")
        raise typer.Exit(code=2)
    try:
        image_ref, image_id = resolve_image(image)
    except RuntimeError as e:
        raise _fail(str(e))
    problem = validate_variant(variant, image=image_ref)
    if problem:
        raise _fail(problem)
    if is_bundled_image(image_id):
        extra = non_bundled_tools(selected)
        if extra:
            raise _fail(f"These cases name tools the bundled agent does not have: {extra}. A forbidden "
                        f"one could never be called and a required one never satisfied, so the result "
                        f"would say nothing. Fix the names, or pass --image for an agent that has them.")
    _print_warnings(variant, image_ref)

    # With --tag (or --cases), the cases that actually ran are the subset the
    # judge must find: recorded as ids, not as the filter that produced them.
    selected_ids = [c["id"] for c in selected] if (ids or tag) else None
    try:
        manifest_path = run_suite(selected, variant, library, workers, category,
                                  selected_ids=selected_ids, tags=tag, image=image_ref,
                                  runs_dir=batch_root, source=lib)
    except BatchInterrupted as e:
        manifest_path = e.manifest_path
    except RuntimeError as e:
        raise _fail(str(e))
    _write_manifest_out(manifest_out, manifest_path)
    raise typer.Exit(code=_summarise(manifest_path))


if __name__ == "__main__":
    app()
