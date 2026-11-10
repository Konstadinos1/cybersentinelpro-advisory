"""Static and heuristic analysis of MCP tool metadata.

Covers classic tool poisoning (malicious text in the tool description) and
Advanced Tool Poisoning Attacks, where the payload lives somewhere reviewers
rarely look: parameter descriptions, defaults, enum values, or the tool's
runtime output.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from aegis.core.findings import Finding, Severity
from aegis.mcp_firewall.models import McpTool
from aegis.mcp_firewall.rules import (
    INJECTION_RULES,
    POISONING_REFERENCES,
    SENSITIVE_PATH_RULE,
    SUSPICIOUS_PARAMETER_NAMES,
    PatternRule,
)
from aegis.mcp_firewall.unicode_smuggling import (
    inspect_hidden_characters,
    strip_hidden_characters,
)

# Legitimate descriptions are short. Very long ones are where payloads hide
# below the fold of an approval dialog.
DESCRIPTION_MAX_CHARS = 2000
SCHEMA_MAX_DEPTH = 12
# A single zero-width joiner can be an emoji artefact; several are a signal.
ZERO_WIDTH_TOLERANCE = 1

SCHEMA_TEXT_KEYS = ("description", "title", "default", "const", "examples", "enum", "pattern")


def _apply_rules(text: str, location: str, rules: tuple[PatternRule, ...]) -> list[Finding]:
    findings: list[Finding] = []
    for rule in rules:
        match = rule.pattern.search(text)
        if match:
            findings.append(
                Finding.build(
                    rule.rule_id,
                    rule.severity,
                    rule.message,
                    location=location,
                    evidence=match.group(0),
                    references=POISONING_REFERENCES,
                )
            )
    return findings


def _hidden_character_findings(text: str, location: str) -> list[Finding]:
    report = inspect_hidden_characters(text)
    findings: list[Finding] = []
    if report.tag_character_count:
        findings.append(
            Finding.build(
                "AEGIS-TP-020",
                Severity.CRITICAL,
                "ASCII smuggling via Unicode Tag characters",
                location=location,
                evidence=report.decoded_tag_payload,
                references=POISONING_REFERENCES,
            )
        )
    if report.bidi_control_count:
        findings.append(
            Finding.build(
                "AEGIS-TP-021",
                Severity.HIGH,
                "Bidirectional control characters can reorder displayed text",
                location=location,
                evidence=f"{report.bidi_control_count} bidi control character(s)",
                references=POISONING_REFERENCES,
            )
        )
    invisible = report.zero_width_count + report.variation_selector_count
    if invisible > ZERO_WIDTH_TOLERANCE:
        findings.append(
            Finding.build(
                "AEGIS-TP-022",
                Severity.HIGH,
                "Zero-width or variation-selector characters hide content",
                location=location,
                evidence=f"{invisible} invisible character(s)",
                references=POISONING_REFERENCES,
            )
        )
    return findings


def scan_text(text: str, location: str) -> list[Finding]:
    """Scan one string as the model would read it.

    Pattern rules run on the visible text, on the text with invisible
    characters removed, and on any decoded tag payload, so splitting a
    trigger phrase with zero-width characters does not evade detection.
    """
    findings = _hidden_character_findings(text, location)
    rules = (*INJECTION_RULES, SENSITIVE_PATH_RULE)
    variants = {text, strip_hidden_characters(text)}
    hidden_payload = inspect_hidden_characters(text).decoded_tag_payload
    if hidden_payload:
        variants.add(hidden_payload)
    seen: set[str] = set()
    for variant in variants:
        for finding in _apply_rules(variant, location, rules):
            if finding.rule_id not in seen:
                seen.add(finding.rule_id)
                findings.append(finding)
    return findings


def iter_strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from iter_strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from iter_strings(item)


def _iter_schema_nodes(
    schema: Any, path: str, depth: int = 0
) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield every sub-schema with a JSON-pointer-like path."""
    if not isinstance(schema, dict) or depth > SCHEMA_MAX_DEPTH:
        return
    yield path, schema
    for name, child in _named_children(schema):
        yield from _iter_schema_nodes(child, f"{path}/{name}", depth + 1)


def _named_children(schema: dict[str, Any]) -> Iterator[tuple[str, Any]]:
    for keyword in ("properties", "$defs", "definitions", "patternProperties"):
        children = schema.get(keyword)
        if isinstance(children, dict):
            for name, child in children.items():
                yield f"{keyword}/{name}", child
    for keyword in ("items", "additionalProperties", "not"):
        if isinstance(schema.get(keyword), dict):
            yield keyword, schema[keyword]
    for keyword in ("anyOf", "oneOf", "allOf", "prefixItems"):
        for index, child in enumerate(schema.get(keyword) or []):
            yield f"{keyword}/{index}", child


def _parameter_name_findings(schema: dict[str, Any], path: str) -> list[Finding]:
    findings: list[Finding] = []
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return findings
    for name in properties:
        findings.extend(_hidden_character_findings(name, f"{path}/properties/{name}"))
        if strip_hidden_characters(name).lower() in SUSPICIOUS_PARAMETER_NAMES:
            findings.append(
                Finding.build(
                    "AEGIS-TP-030",
                    Severity.HIGH,
                    "Covert side-channel parameter",
                    location=f"{path}/properties/{name}",
                    evidence=name,
                    references=POISONING_REFERENCES,
                )
            )
    return findings


def scan_schema(schema: dict[str, Any], root: str = "inputSchema") -> list[Finding]:
    """Scan every text-bearing keyword of a JSON Schema, at any depth."""
    findings: list[Finding] = []
    for path, node in _iter_schema_nodes(schema, root):
        findings.extend(_parameter_name_findings(node, path))
        for key in SCHEMA_TEXT_KEYS:
            for text in iter_strings(node.get(key)):
                findings.extend(scan_text(text, f"{path}/{key}"))
    return findings


def scan_tool(tool: McpTool) -> list[Finding]:
    """Return all findings for a tool's advertised metadata."""
    findings = scan_text(tool.name, "name") + scan_text(tool.description, "description")
    if len(tool.description) > DESCRIPTION_MAX_CHARS:
        findings.append(
            Finding.build(
                "AEGIS-TP-040",
                Severity.MEDIUM,
                "Description is unusually long; payloads hide below the fold",
                location="description",
                evidence=f"{len(tool.description)} characters",
                references=POISONING_REFERENCES,
            )
        )
    findings.extend(scan_schema(tool.input_schema))
    extras = tool.model_extra or {}
    for key, value in extras.items():
        for text in iter_strings(value):
            findings.extend(scan_text(text, key))
    return findings


def scan_tool_result(result: Any) -> list[Finding]:
    """Scan a ``tools/call`` result for instructions aimed at the model (ATPA)."""
    findings: list[Finding] = []
    for text in iter_strings(result):
        findings.extend(scan_text(text, "result"))
    return findings
