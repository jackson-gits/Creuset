# Score reports — 2026-09-20

Evidence behind the Results tables in `README.md` and CLAUDE.md's "Current state".

All adversarial transcripts come from one agent model (`openai/gpt-oss-20b`) and one
agent build (with the `FINALIZER_MAX_TOKENS` fix), 26/26 cases per variant.
Judge model: `openai/gpt-oss-120b`, `JUDGE_SAMPLES=3` (median).

| File | What it is | `valid` |
|---|---|---|
| `rules_{naive,hardened,broken}.json` | Adversarial, **rule layer only** (`--skip-model-judge`) | ✅ all three |
| `full_hardened.json` | Adversarial, rule + LLM judge | ✅ |
| `full_{naive,broken}.json` | Adversarial, rule + LLM judge | ❌ judge TPD exhausted mid-run |
| `bn_rules_{naive,hardened,broken}.json` | Benign suite, rule layer (false positives) | ✅ / ✅ / ❌ (BN-010 unrun) |
| `rollback_latency.json` | Injection → traffic moved, from the monitor's incident stamps | — |

**Read `valid` before quoting any number.** `full_naive.json` reports a 26/26 detection
rate that is entirely an artifact of the judge being unreachable: every judge error
fails closed, and fail-closed counts as a detection.

Source batches under `logs/runs/` (gitignored):
`20260920-045833_naive_attack_library`, `20260920-054506_hardened_attack_library`,
`20260920-043334_broken_attack_library`, `20260920-144442_naive_benign_tasks`,
`20260920-055017_hardened_benign_tasks`, `20260920-144532_broken_benign_tasks`.
