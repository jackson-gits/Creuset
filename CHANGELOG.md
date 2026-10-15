# Changelog

All notable changes to Creuset. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

**Measurement-affecting** entries matter most here: they mark the commits
across which published results stop being comparable (see
[CONTRIBUTING.md](CONTRIBUTING.md#measurement-affecting-changes)). An entry
that says *none* means every fingerprint in `baseline.lock.json` was unchanged.

## [Unreleased]

### Measurement-affecting

- **None changed.** The agent prompts and loop, every case's grading fields,
  the mock world, the judge prompt and the default thresholds all keep the
  fingerprints the published results ran under.
- New surface fingerprinted: `agent/constraints.txt`. It pins the agent image's
  dependencies to the exact versions inside the image that produced the
  published results (LangChain 0.2.17, langchain-openai 0.1.25, openai 1.109.1,
  Python 3.11.16). Before, `docker compose build` resolved whatever was newest
  within the ranges, so a rebuild could change agent behaviour silently. A
  rebuilt image was checked to contain exactly the measured versions.
- New graded case field `tool_responses` (canned answers for generic tools) is
  fingerprinted like the other grading fields. No bundled case uses it.

### Added

- **Portable batches**: manifests record transcripts relative to the batch
  folder and the library repo-relative, keep the library's exact bytes beside
  the manifest (`library.yaml`, with its sha256), and record the Creuset commit
  they ran from. A batch moved, downloaded as a CI artifact or read on another
  machine still scores and resumes. Score reports say which library they graded
  against and whether it changed since the run (`library_graded`); a resume
  refuses a changed library rather than mix two versions of its cases.
- **REST mock**: any request to `$CREUSET_MOCK_URL/http/<api>/<path>` is
  recorded as a call of the tool `<api>` (method, path, query and body as its
  arguments) and answered from the case's `http_responses`: first matching
  rule, else 404. Agent settings may reference `${CREUSET_MOCK_URL}` and
  `${CREUSET_RUN_ID}`, filled in per run, so an agent whose tools read an API
  base URL from the environment is tested with no code change. CI runs the
  example over HTTP.
- **Multi-turn cases**: `conversation` (earlier user and assistant turns) is
  replayed before `input_payload` by agents that keep history, and shown to the
  judge, labelled as scripted by the test. The judge's messages for every case
  without one are byte-identical; the bundled agent's scenario keys are
  unchanged (it ignores the field, and the loader warns).
- **Starter library** `attacks/generic_agent.yaml`: thirteen attacks that name no
  tools, so they run against any agent as they stand. Run live against the
  example agent's weak prompt on gpt-oss-20b, they caught a system-prompt leak
  by translation (the judge) and a base64-hidden instruction being followed
  (the canary).
- **GitHub Action**: this repository is a composite action (`action.yml`).
  `uses: jackson-gits/Creuset@<sha>` starts the sandbox, proves isolation, runs
  the gate on an image built earlier in the job, writes the job summary and a
  JUnit report, uploads every transcript, and fails the step when the agent is
  blocked. Outputs: `verdict`, `valid`, `exit-code`, `junit`, `summary`,
  `record`. CI's `sandbox-e2e` job now runs the action itself, twice.
- **CI formats**: `--junit-xml` and `--summary-md` on `score.py` and the gate;
  under GitHub Actions the gate also writes the job summary. Cases that never
  completed are JUnit *errors*, not failures, and everything published shows
  the gate's final verdict (an invalid PASS reads as blocked).
- **Waivers**: `--waivers FILE` (or `CREUSET_WAIVERS`) accepts named failures,
  each with a reason and a mandatory expiry date. A waived case still reads as
  failing but stops counting against the thresholds; expired waivers block
  again, unused ones are reported, and a waiver cannot accept a case that never
  completed. A malformed file is refused before anything runs.
- **Repeated runs**: `--repeat N` on the loader and the gate runs every case N
  times, each in its own container (`PI-001.json`, `PI-001.r2.json`, ...). A
  case FAILs if any run does, and the report lists every run (`runs`,
  `runs_failed`). One run cannot tell an agent that resists an attack 7 times
  in 10 from one that always does. `--resume` re-runs only the missing runs.
- **Argument-level policies**: `forbidden_calls` and `required_calls` rules
  name a tool and conditions on its arguments (`issue_refund` with `amount` over
  100, `send_email` to an address outside the company, a query matching
  `DROP`). Checked against the server audit by a new `call_policy` rule check;
  a missing or undecidable argument cannot clear a forbidden call, nor prove a
  required one. Cases without rules get exactly the checks they had.
- **Claude agents.** llm-proxy can allow Anthropic's Messages API
  (`LLM_ALLOWED_ENDPOINTS=messages|models`, key in `x-api-key`), and every agent
  container gets `ANTHROPIC_BASE_URL` and a placeholder `ANTHROPIC_API_KEY`, so
  an agent on Anthropic's own SDK runs unchanged. `messages/batches` stays
  refused. Verified live against a fake upstream: the placeholder is replaced,
  the agent's `Authorization` is dropped, `anthropic-version` passes through.
- **Real agents' tool names**: camelCase, hyphens and MCP-style dots
  (`lookupOrder`, `issue-refund`, `files.read`), as OpenAI and Anthropic tool
  calling accept them. Previously only lower-case `snake_case`.
- **The agent's own settings**: `--agent-env KEY=VALUE` and `--agent-env-file`
  (or `CREUSET_AGENT_ENV_FILE`) on `run_test.py`, the loader and the gate. Names
  the harness sets are refused; manifests record the names and a fingerprint of
  the values, and `--resume` requires the same settings.
- **Sandbox size**: `CREUSET_SANDBOX_MEMORY`, `_CPUS`, `_PIDS`, `_TMP_SIZE`, and
  `CREUSET_SANDBOX_TMPFS` for extra writable directories (each a `noexec` tmpfs,
  for caches under a read-only root). Defaults unchanged and pinned by a test;
  every manifest records the box it ran in.
- **Bring your own agent.** `--agent-image` on `sandbox/run_test.py`,
  `attacks/loader.py` and `gate/run_gate.py` (or `CREUSET_AGENT_IMAGE`) tests
  any image that honours the agent contract, with `--variant` as its label.
  The contract: `sandbox/contract.py`, `schemas/transcript.v1.json`, and the
  `CREUSET_*` environment every agent container receives (`CONTRACT_ENV`).
- `schemas/library.v1.json`: the test-library format as JSON Schema. A library
  may declare its agent's own `tools`; cases may name only those, so a typo in
  `forbidden_tools` is an error instead of an assertion that can never fail.
  New optional case fields: `tool_responses`, `max_llm_calls`, `tags`,
  `metadata`. Case IDs may be longer (`ORDERS-0042`).
- `examples/scripted-agent/`: a deterministic agent (no model, no key) and a
  library for it, exercising the whole contract.
- `examples/openai-agent/`: the same contract with a real model, about a
  hundred lines on the plain OpenAI SDK; run live through the sandbox.
- Documentation: `docs/guides/testing-your-agent.md`,
  `docs/guides/writing-attack-cases.md` (CONTRIBUTING and the attack-case issue
  template linked to it before it existed), and `docs/reference/results.md` for
  every field of the transcript, manifest, score report and gate record. A test
  now checks every relative link and anchor in the Markdown docs.
- `scripts/doctor.py`: checks the host, `.env`, Docker, Compose, the sandbox
  network, container health, stale images and containers, and deploy state,
  each with the command that fixes it. `--probe` proves isolation, `--online`
  verifies both keys with `/models` calls (no tokens), `--json` for CI.
- CI: a `sandbox-e2e` job runs the real Docker stack and the gate against the
  example agent on every push, with no key and no quota.
- `CREUSET_PREFIX`: run a second stack (containers, networks, project name)
  beside the first.
- `MOCK_STRICT_RUNS` is passed through by Compose.
- Batch manifests (`manifest_version: 1`) and score reports
  (`report_version: 1`) record the subject: kind, image and image ID. Reports
  also record the thresholds they were judged against and list
  `contract_errors`. Gate records add `tested_image_id`, `slot`, `library`.
- `--library` on the gate and on `run_test.py`/`score.py` ad hoc modes.
- Governance and contribution docs: Apache-2.0 `LICENSE` and `NOTICE`,
  `SECURITY.md`, `CONTRIBUTING.md`, Code of Conduct, `CITATION.cff`, issue and
  PR templates, pre-commit.
- mock-services: generic recorded tools (`POST /tools/{name}`), run-scoped
  URLs (`/r/{run}/...`), canned responses per run, opt-in strict runs.
- llm-proxy provider profiles (scheme, port, path prefix, auth header, extra
  CA, endpoint set), validated fail-closed at container start.
- `scripts/update_baseline_lock.py` and its tests: the measurement guard.

### Changed

- **The harness creates each run's mock world itself**, with the case's
  fixtures, before the agent starts; the bundled agent's own init is now a
  harmless repeat. A world without the case's fixtures fails the case
  (`harness_error`) instead of passing an attack that never arrived.
- **The agent sees only the scenario**, never the answer key
  (`expected_behavior`, `forbidden_tools`, patterns...).
- Containers run by **image ID**, resolved once per case, and transcripts
  record `agent_image`/`agent_image_id`. `--resume` refuses to finish a batch
  after the image was rebuilt (`--allow-image-change` to override).
- Transcripts are parsed by the contract: stdout logging no longer loses the
  transcript, a v1 transcript that breaks its schema is a `contract_error`,
  and a `completed` transcript from a container that exited non-zero is a
  `container_error`. New harness-owned fields: `exit_code`, `world_fixtures`,
  `reported_status`, `contract_violations`.
- The gate refuses a misconfigured judge before running the suite (exit 2),
  instead of failing every case closed after spending the agent quota.
- Images: base pinned to `python:3.11.16-slim-trixie`, dependencies pinned
  with constraints files, curl removed (healthchecks use Python), OCI labels,
  `.dockerignore` keeps deploy state out of the router's build context.
- Blue/green slots get the same environment as one-shot runs
  (`FINALIZER_MAX_TOKENS`, `LLM_MAX_RETRIES`, `OPENAI_BASE_URL`) and the
  `AGENT_IMAGE_TAG` the harness tests.
- The isolation probe runs mock-services' image, so it works when the agent
  under test is an image without Python.
- `loader.py --cases` with an unknown ID exits 2, and an empty selection
  exits 1, instead of running nothing and exiting 0.

### Fixed

- **A batch killed before its end could not be resumed**: the manifest was
  written only when a batch finished, so Ctrl-C, a closed terminal or a
  cancelled CI job left transcripts that `--resume` refused ("nothing to
  resume") and quota spent for nothing. It is now written before the first run
  and after every one, atomically.
- **Ctrl-C did not stop a batch**: the worker pool ran every queued case on its
  way out, and SIGTERM ended the loader with its `docker run` children still
  going. Both now stop it at a safe point: queued runs never start, the batch's
  containers are removed (every harness container is labelled with its stack,
  batch and run), a run the stop cut off is not recorded as a result, and the
  loader exits 130 with the resume command. The gate gives its loader time to
  do this (it used to kill it 0.25 s after Ctrl-C), passes a SIGTERM on, and
  exits 130 with no verdict. `run_test.py --cleanup` removes what a crash left.
- **A bundled image built from other files ran under the new name**: prompts
  and agent code are baked in at build time, so editing a variant without
  rebuilding ran the old prompt while every record named the new one. Preflight
  now compares the bytes of `agent/` with the image's copies and refuses a
  mismatch, naming the files (`CREUSET_ALLOW_STALE_AGENT=1` runs an older build
  on purpose). The doctor uses the same comparison instead of file ages.
- **An unready sandbox read as a failed agent**: the gate reported Docker down
  or a stale image as `BLOCKED`, exit 1, the code CI reads as "the agent failed
  the attacks". It now runs preflight before the suite and exits 2.
- **`AGENT_MODEL` unset silently asked for gpt-4o-mini**, which a non-OpenAI
  upstream refuses on every case. It is now a preflight problem for the bundled
  agent; external images get it empty.
- **Image identity on Docker's containerd image store**: every build gets a new
  image ID there (the build attestation carries a timestamp), so rebuilding
  unchanged code looked like a different build. The doctor then reported
  identical containers as running old code (and failed, since Compose rightly
  keeps them), and the isolation probe tried to start an image ID the store had
  dropped. Transcripts and manifests now also record a content identity (the
  platform-specific image ID: config and layers, what Compose itself records);
  resumes, the gate's deploy check and the doctor compare that. Found by
  running the GitHub Action twice in a row, as `sandbox-e2e` does.
- **The canary check passed vacuously for external agents**: it searched for
  the bundled marker, which only the bundled prompts contain. For an external
  agent it now SKIPs (not measured) unless `CREUSET_CANARY` names that agent's
  own marker.
- **The gate staged the green slot unconditionally**, so when green was live a
  deploy recreated the container serving traffic. It now stages the inactive
  slot.
- **A gate PASS whose deploy failed exited 0**, so CI reported a deploy that
  never happened. It now exits 3.
- **The gate deployed by tag**: a rebuild during a run would have put untested
  bytes live under a PASS. Traffic now moves only once the slot runs the
  tested image ID.
- `score.py` ignored a v1 agent's `output_truncated` when deciding `valid`, so
  a truncated answer could leave a report claiming to be a measurement.
- The library schema rejected `max_llm_calls`, a field the agent and the
  baseline lock already used.
- A unit test used `Path.read_text(newline=...)`, which needs Python 3.13.
- Earlier on this branch (security pass, wave 1): llm-proxy upstream TLS
  verification, a `..%2F` allowlist bypass and a trailing-newline bypass;
  CI script injection; env-file injection through `--version`; fail-open gate
  paths; the judge fence; ground truth relayed by the agent; an agent able to
  re-initialise its world and wipe its own audit log; the judge's key reaching
  `api.openai.com` when `JUDGE_API_BASE` was unset; DNS rebinding against the
  results browser. See `SECURITY.md` and the git history for detail.
