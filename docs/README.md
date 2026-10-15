# Creuset documentation

Start with the [README](../README.md): what Creuset is, the published results,
and the quick start.

**Guides**

- [Testing your own agent](guides/testing-your-agent.md): the agent contract,
  the two example agents, reading results, running the gate in CI.
- [Writing attack cases](guides/writing-attack-cases.md): choosing each field,
  the mock world, writing payloads that measure something.

**Reference**

- [Results](reference/results.md): every field of the transcript, manifest,
  score report and gate record, and the gate's exit codes.
- [`schemas/transcript.v1.json`](../schemas/transcript.v1.json) and
  [`schemas/library.v1.json`](../schemas/library.v1.json): the two contracts as
  JSON Schema.
- [`deploy/README.md`](../deploy/README.md): blue/green, the router, and how
  the gate deploys.

**Project**

- [CONTRIBUTING.md](../CONTRIBUTING.md): checks, measurement-affecting
  changes, commit style.
- [SECURITY.md](../SECURITY.md): reporting a vulnerability in Creuset itself.
- [CHANGELOG.md](../CHANGELOG.md)
- [Development log](development-log.md): how the project got here, session by
  session, including the mistakes and how each was found.
- [CLAUDE.md](../CLAUDE.md): working notes. The architecture, the facts that
  are easy to get wrong, what is load-bearing, and what is still open.
