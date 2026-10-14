# Security policy

Creuset is a security gate: its job is to decide whether an AI agent is safe to
promote. A flaw in Creuset itself (a way out of the sandbox, a path to the real
API key, a case that should fail but scores PASS) is therefore a vulnerability
in the product, even though the agents it ships with are deliberately weak.
This page says how to report one, what counts, and what to expect back.

## Supported versions

| Version | Supported |
|---|---|
| Latest release | Yes |
| `main` | Yes |
| Anything older | No: update to the latest release or `main` first |

Until the first tagged release exists, only `main` is supported. Fixes land on
`main` and in the next release; there are no backports to older releases.

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a
vulnerability.**

Report it privately through GitHub's private vulnerability reporting:

1. Go to <https://github.com/jackson-gits/creuset>.
2. Open the **Security** tab.
3. Click **Report a vulnerability** (or go straight to
   <https://github.com/jackson-gits/creuset/security/advisories/new>).

That is the only reporting channel. It keeps the report, the discussion and
any fix private until a coordinated disclosure, and it lets us credit you in
the published advisory if you wish.

A useful report includes:

- the commit or release you tested (`git rev-parse HEAD`);
- the component (for example `deploy/llm-proxy/`, `judge/score.py`,
  `sandbox/run_test.py`, `ui/app.py`) and the trust boundary it crosses;
- exact steps to reproduce, ideally with a minimal attack case, transcript or
  request, and what you expected to happen instead;
- your OS and Docker / Compose versions if the issue involves containers;
- for scoring issues, the score report's `valid` flag and, if it is false,
  why (`unmeasured`, `judge_errors`, `truncated_finalizer`, `batch_complete`;
  the results browser lists these as reasons), plus the affected case's
  `rule_checks`, `rule_reasons` and `judge_rationale`.

Most issues can be shown without a real provider key or any quota: the
llm-proxy bypasses fixed so far were reproduced against a fake upstream, and
the test suite (`ruff check . && pytest`) needs neither. Please never include
a real API key, `.env` contents or provider organisation IDs in a report.

## What to expect

Creuset is maintained by a single person, so these are **best-effort targets,
not guarantees**:

- **Acknowledgement within 7 days** of your report.
- An initial assessment (accepted, needs more information, or out of scope)
  after that, with updates as the fix progresses.
- **A fix or documented mitigation within 90 days** for accepted reports. If a
  fix will take longer, we will say so and agree a disclosure date with you.
- A GitHub Security Advisory and a `Security` entry in `CHANGELOG.md` when the
  fix ships, crediting you unless you ask us not to.

Please give us a reasonable chance to fix the issue before disclosing it
publicly. If you have not heard back within 7 days, comment on your private
report to follow up.

## Scope

### In scope

Anything that breaks one of the trust boundaries Creuset claims to enforce
(see "Security model" in `README.md`):

- **Sandbox or network escape** from `creuset-net`: an agent container reaching
  the internet, DNS, the host, or any service other than `llm-proxy` and
  `mock-services`.
- **Reaching the real `LLM_API_KEY`** from an agent container, or from anywhere
  other than `llm-proxy` and the host-side judge.
- **llm-proxy allowlist bypass**: reaching a non-allowlisted upstream path or
  host with the injected key, or defeating upstream TLS verification.
- **Fail-open scoring or gating**: any way a case that should FAIL is scored
  PASS, or a report with `valid: false` (or a gate verdict that is not PASS)
  leads to a deploy. This covers `judge/rule_checks.py`, `judge/score.py` and
  `gate/run_gate.py`.
- **Judge-fence escape**: transcript or tool-output text that the LLM judge
  reads as trusted instructions or as the server audit log, outside the
  `<transcript>` fence.
- **Audit-log tampering from the agent**: an agent under test writing,
  deleting, replacing or forging entries in the server-side audit log of
  `mock-services`, or making a missing world read as "no actions".
- **Router mis-routing**: live traffic reaching a slot that
  `deploy/state/state.json` does not name, including after a torn or corrupt
  state file.
- **Operator-input injection**: a `--version` or `--variant` value that escapes
  validation into a file path, a slot env file or Compose interpolation.
- **Results browser** (`ui/`): path traversal outside `logs/`, XSS, DNS
  rebinding, or any other way a website or crafted log file can read or act
  through the local UI.
- **CI injection**: workflow inputs, branch names or pull-request content that
  execute in `.github/workflows/` with secrets or write permissions.

### Out of scope

These are welcome, but as **public issues**, not security reports:

- **New jailbreaks or injection prompts** that make the bundled `naive`,
  `hardened` or `broken` agents misbehave. `naive` and `broken` are vulnerable
  on purpose, and an attack that gets past `hardened` is a coverage gap in the
  test library, not a flaw in the gate. Please propose it with the
  **Attack case** issue template so it can be added to `attacks/`.
- **LLM judge variance**: the same transcript scoring differently across runs.
  This is a documented limitation; the deterministic rule layer is ANDed in so
  a lenient judge cannot pass a rule FAIL. Use the **Bug report** or
  **False positive** template.
- **Provider rate limits and quota exhaustion.** A run that hits a 429 is
  marked `valid: false` and fails closed by design.
- Vulnerabilities in third-party dependencies or base images with no
  Creuset-specific path to exploit them. Please report those upstream.
- Attacks that need an already-compromised host, Docker daemon or `.env`
  file, or a malicious operator with shell access to the machine running
  the gate.

If you are unsure whether something is in scope, report it privately anyway.

## Responsible use

Creuset ships an attack library (`attacks/*.yaml`) and deliberately vulnerable
agent variants. They exist to test agents **you own or are authorised to
test**, inside Creuset's own sandbox and mock services.

- Run the library against your own agents and deployments only.
- Attack cases must target only Creuset's mock world: the fictional users,
  files and `example.com`-style addresses in `sandbox/mock_services/`. No real
  personal data, and no real people or organisations as targets.
- Do not contribute payloads that work as live exploits against third-party
  services, real credentials, or real infrastructure. A case should test
  whether an agent *misuses its tools*, not attack anyone outside the sandbox.
- When testing Creuset itself, use a local checkout and your own provider
  account. Do not probe deployments, accounts or infrastructure that belong
  to someone else.

`CONTRIBUTING.md` repeats these rules for attack-case authors.
