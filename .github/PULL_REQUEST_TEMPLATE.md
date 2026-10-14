## What and why

<!-- What does this change, and what problem does it solve? Link the issue. -->

## How it was tested

<!-- Commands you ran and what they printed. If you did a live run, give the
     model, variants, layer (rule-only / rule+judge) and each report's `valid`. -->

## Checklist

- [ ] `ruff check . && pytest` pass locally (no Docker, key or quota needed).
- [ ] `python attacks/loader.py --dry-run` passes, if anything under `attacks/` changed.
- [ ] Existing CLI flags, script entry points and report / manifest / transcript fields still work, or the break is called out above.
- [ ] Docs and `CHANGELOG.md` are updated where behaviour, flags, env vars or report fields changed.
- [ ] No API keys, `.env` contents, provider organisation IDs or real personal data in the diff.
- [ ] If this touches a trust boundary (`deploy/llm-proxy/`, `sandbox/`, `judge/`, `gate/`, `.github/workflows/`), it still fails closed, and a test shows it.

## Measurement-affecting surfaces

Does this PR change anything that decides what the published results mean? That
is: `agent/variants/*.txt`, `agent/run_agent.py`, `agent/tools.py`,
`agent/callbacks.py`, the grading fields of a case in `attacks/*.yaml`,
mock-services' `_BASE_FILES` / `_BASE_DB` / `_FIXTURES`, the judge's prompts or
message formatting, the default thresholds, or the agent's dependency versions.
See "Measurement-affecting changes" in CONTRIBUTING.md.

- [ ] **No.** `tests/test_baseline_lock.py` and `tests/test_judge_prompt_snapshot.py` pass without regenerating anything.
- [ ] **Yes, deliberately.** All of the following are done:
  - [ ] `baseline.lock.json` regenerated with `python scripts/update_baseline_lock.py` (and the judge snapshot, if the judge's messages changed)
  - [ ] a **Measurement-affecting** entry in `CHANGELOG.md`
  - [ ] the affected results re-run (described above), or the published numbers stated as no longer applying
  - [ ] the change is in its own PR, not mixed with unrelated work
