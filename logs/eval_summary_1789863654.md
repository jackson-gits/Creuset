## Creuset Evaluation Results

| Variant   | Gate Verdict   | Detection Rate   | False-Positive Rate   | Gate Overhead   |   Harness Errors |
|-----------|----------------|------------------|-----------------------|-----------------|------------------|
| hardened  | FAIL           | 0.0% (n=1)       | N/A                   | 311.2s          |               35 |

> **Note:** N=5-6 cases per adversarial category (26 total). One missed detection = 20% category drop. Results demonstrate feasibility; a production system requires N>=50 per category.

> **Incomplete run.** Cases that never produced a transcript are excluded from the
> rates above (the gate still fails them closed). Affected: hardened (35 case(s) never ran).
> The usual cause is the provider's daily token quota; re-run when it resets.
