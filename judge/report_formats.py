"""
judge/report_formats.py
────────────────────────
The score report in the shapes CI systems read: JUnit XML (GitHub, GitLab,
Jenkins and most others render it as a test report) and a Markdown summary
(GitHub's job summary, a PR comment, a chat message).

Both say the same three things the JSON report does, in the same order of
importance: the verdict, whether it is a measurement at all (`valid`), and
what failed and why. A FAIL on a case that never completed is reported as an
error, not a failure: it is infrastructure, not a finding about the agent.
"""

from __future__ import annotations

import datetime as dt
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional


def _measured(result: Dict[str, Any]) -> bool:
    return (result.get("status") == "completed" and not result.get("judge_error")
            and not result.get("finalizer_truncated"))


def _why(result: Dict[str, Any]) -> str:
    reasons = list(result.get("rule_reasons") or [])
    if result.get("judge_verdict") == "FAIL" and result.get("judge_rationale"):
        reasons.append(f"Judge (score {result.get('judge_score')}): {result['judge_rationale']}")
    if result.get("judge_error"):
        reasons.append(f"Judge unreachable: {result['judge_error']}")
    return "\n".join(reasons) or "No reason recorded."


def junit_xml(report: Dict[str, Any], suite: Optional[str] = None) -> str:
    """The report as JUnit XML: one testcase per case."""
    results: List[Dict[str, Any]] = report.get("results") or []
    subject = report.get("subject") or {}
    failures = errors = skipped = 0
    cases = []
    for r in results:
        case = ET.Element("testcase", {"classname": f"creuset.{r.get('category', 'unknown')}",
                                       "name": f"{r.get('test_id', '?')} [{r.get('severity', '?')}]"})
        if r.get("final") != "PASS":
            if r.get("waived"):
                w = r["waived"]
                skipped += 1
                ET.SubElement(case, "skipped", {"message": f"FAILED, waived until {w['expires']}: {w['reason']}"})
            elif not _measured(r):
                errors += 1
                node = ET.SubElement(case, "error", {"type": "not-measured",
                                                     "message": f"Did not complete: status {r.get('status')}"})
                node.text = _why(r)
            else:
                failures += 1
                first = (r.get("rule_reasons") or [r.get("judge_rationale") or "FAIL"])[0]
                node = ET.SubElement(case, "failure", {"type": "rule" if r.get("rule_verdict") == "FAIL" else "judge",
                                                       "message": str(first)[:300]})
                node.text = _why(r)
        if r.get("output_preview"):
            ET.SubElement(case, "system-out").text = str(r["output_preview"])
        cases.append(case)

    name = suite or f"creuset: {report.get('variant')} x {_library_name(report)}"
    attrs = {"name": name, "tests": str(len(results)), "failures": str(failures), "errors": str(errors),
             "skipped": str(skipped),
             "timestamp": dt.datetime.fromtimestamp(report.get("ts") or 0, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")}
    root = ET.Element("testsuites", {k: v for k, v in attrs.items() if k != "timestamp"})
    testsuite = ET.SubElement(root, "testsuite", attrs)
    properties = ET.SubElement(testsuite, "properties")
    for key, value in (("gate_verdict", report.get("gate_verdict")), ("valid", report.get("valid")),
                       ("agent_image", subject.get("image")), ("agent_image_id", subject.get("image_id")),
                       ("agent_model", (report.get("models") or {}).get("agent")),
                       ("judge_model", (report.get("models") or {}).get("judge")),
                       ("repeat", report.get("repeat", 1))):
        ET.SubElement(properties, "property", {"name": key, "value": str(value)})
    testsuite.extend(cases)
    ET.indent(root)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode") + "\n"


def _library_name(report: Dict[str, Any]) -> str:
    library = str(report.get("library") or "?")
    return library.replace("\\", "/").rsplit("/", 1)[-1]


def _cell(text: Any, limit: int = 160) -> str:
    """One Markdown table cell: no pipes or newlines, clipped."""
    text = " ".join(str(text).split()).replace("|", "\\|")
    return text if len(text) <= limit else text[:limit - 1] + "…"


def markdown_summary(report: Dict[str, Any], decision: Optional[str] = None) -> str:
    """A short Markdown account: verdict, validity, thresholds, then what failed."""
    verdict = report.get("gate_verdict", "FAIL")
    head = "✅ PASS" if verdict == "PASS" else "❌ FAIL"
    if decision:
        head += f" ({decision.replace('_', ' ').lower()})"
    subject = report.get("subject") or {}
    models = report.get("models") or {}
    lines = [f"### Creuset gate: {head}", ""]
    facts = [f"variant `{report.get('variant')}`", f"library `{_library_name(report)}`"]
    if subject.get("image"):
        image_id = str(subject.get("image_id") or "")[:19]
        facts.insert(0, f"image `{subject['image']}`" + (f" (`{image_id}`)" if image_id else ""))
    facts.append(f"agent model `{models.get('agent')}`")
    facts.append(f"judge `{models.get('judge')}`" if models.get("judge") else "rule layer only")
    if int(report.get("repeat") or 1) > 1:
        facts.append(f"{report['repeat']} runs per case")
    lines += [" · ".join(facts), ""]

    if not report.get("valid"):
        causes = []
        for key, label in (("unmeasured", "did not complete"), ("judge_errors", "judge unreachable"),
                           ("truncated_finalizer", "answer truncated"), ("contract_errors", "broke the contract")):
            if report.get(key):
                causes.append(f"{label}: {', '.join(report[key])}")
        if report.get("batch_complete") is False:
            causes.append("the batch stopped early")
        lines += ["> [!WARNING]",
                  "> **Not a valid measurement.** The verdict is fail-closed, but its rates say nothing "
                  "about the agent. " + "; ".join(causes), ""]

    lines += ["| Severity | Passed | Threshold | |", "|---|---|---|---|"]
    for severity, d in (report.get("aggregation") or {}).items():
        if not d.get("count"):
            lines.append(f"| {severity} | — | {d['threshold']:.0%} | |")
            continue
        lines.append(f"| {severity} | {d['passed']}/{d['count']} | {d['threshold']:.0%} | "
                     f"{'✅' if d['met'] else '❌'} |")
    lines.append("")

    failed = [r for r in report.get("results") or [] if r.get("final") != "PASS"]
    blocking = [r for r in failed if not r.get("waived")]
    if blocking:
        lines += [f"<details{' open' if len(blocking) <= 10 else ''}><summary>{len(blocking)} failing "
                  f"case(s)</summary>", "", "| Case | Severity | Why |", "|---|---|---|"]
        for r in blocking:
            label = r.get("test_id", "?") if _measured(r) else f"{r.get('test_id', '?')} (not measured: {r.get('status')})"
            if r.get("runs_failed"):
                label += f" — {r['runs_failed']}/{len(r.get('runs') or [])} runs"
            lines.append(f"| {_cell(label, 80)} | {r.get('severity')} | {_cell(_why(r))} |")
        lines += ["", "</details>", ""]
    waived = [r for r in failed if r.get("waived")]
    if waived:
        lines += ["**Waived** (failing, accepted until the date shown):", ""]
        lines += [f"- `{r.get('test_id', '?')}` until {r['waived']['expires']}: {_cell(r['waived']['reason'], 200)}"
                  for r in waived]
        lines.append("")
    waivers = report.get("waivers") or {}
    if waivers.get("expired"):
        lines += [f"Expired waivers, now blocking again: {', '.join(waivers['expired'])}", ""]
    return "\n".join(lines)


def junit_error(message: str, suite: str = "creuset gate") -> str:
    """JUnit XML for a gate that produced no report: one errored testcase saying why."""
    root = ET.Element("testsuites", {"name": suite, "tests": "1", "failures": "0", "errors": "1", "skipped": "0"})
    testsuite = ET.SubElement(root, "testsuite", {"name": suite, "tests": "1", "failures": "0",
                                                  "errors": "1", "skipped": "0"})
    case = ET.SubElement(testsuite, "testcase", {"classname": "creuset", "name": "gate"})
    ET.SubElement(case, "error", {"type": "gate", "message": message[:300]}).text = message
    ET.indent(root)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode") + "\n"
