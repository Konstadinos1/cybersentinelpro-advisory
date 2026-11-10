"""Report renderers: Markdown for humans, JUnit XML for CI, JSON for tooling."""

from __future__ import annotations

import json
from xml.etree.ElementTree import Element, SubElement, tostring

from aegis.redteam.models import CaseResult, SuiteReport

PASS_MARK = "PASS"  # noqa: S105 - a status label, not a credential
FAIL_MARK = "FAIL"


def _status(result: CaseResult) -> str:
    return PASS_MARK if result.passed else FAIL_MARK


def _cell(text: str) -> str:
    """Escape a value for a Markdown table cell."""
    return text.replace("|", "\\|").replace("\n", " ")


def to_markdown(report: SuiteReport) -> str:
    total = len(report.results)
    lines = [
        "# aegis-mcp red-team report",
        "",
        f"- Cases: **{total}**, failed: **{len(report.failures)}**",
        f"- Attacks blocked: **{report.attack_block_rate:.0%}**",
        f"- Benign requests allowed: **{report.benign_pass_rate:.0%}**",
        "",
        "| Status | ID | Module | Title | Expect | Outcome |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for result in report.results:
        case = result.case
        lines.append(
            f"| {_status(result)} | {case.id} | {case.module} | {_cell(case.title)} "
            f"| {case.expect.value} | {_cell(result.outcome.detail)} |"
        )
    return "\n".join(lines) + "\n"


def to_junit(report: SuiteReport) -> str:
    suite = Element(
        "testsuite",
        name="aegis-redteam",
        tests=str(len(report.results)),
        failures=str(len(report.failures)),
    )
    for result in report.results:
        case = SubElement(
            suite, "testcase", classname=f"redteam.{result.case.module}", name=result.case.id
        )
        if not result.passed:
            failure = SubElement(case, "failure", message=result.case.title)
            failure.text = f"expected {result.case.expect.value}; {result.outcome.detail}"
    return tostring(suite, encoding="unicode", xml_declaration=True)


def to_json(report: SuiteReport) -> str:
    document = {
        "summary": {
            "cases": len(report.results),
            "failed": len(report.failures),
            "attack_block_rate": report.attack_block_rate,
            "benign_pass_rate": report.benign_pass_rate,
        },
        "results": [result.model_dump(mode="json") for result in report.results],
    }
    return json.dumps(document, indent=2)


RENDERERS = {"markdown": to_markdown, "junit": to_junit, "json": to_json}
