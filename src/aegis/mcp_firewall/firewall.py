"""Intercepting inspector for MCP ``tools/list`` and ``tools/call``.

The firewall sits between the agent host and an MCP server. It is
default-deny: a tool reaches the model only if it is clean AND its digest
matches a human-approved pin.
"""

from __future__ import annotations

from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from pydantic import ValidationError

from aegis.core.audit import audit_event
from aegis.core.findings import Finding, Severity, worst_severity
from aegis.mcp_firewall.models import (
    CallVerdict,
    McpTool,
    ToolCall,
    ToolsListVerdict,
    ToolVerdict,
)
from aegis.mcp_firewall.pinning import PinStatus, ToolManifest
from aegis.mcp_firewall.rules import POISONING_REFERENCES
from aegis.mcp_firewall.scanner import iter_strings, scan_text, scan_tool, scan_tool_result

BLOCKING_SEVERITY = Severity.HIGH
MAX_ARGUMENT_ERRORS_REPORTED = 5


def _finding(rule_id: str, severity: Severity, message: str, evidence: str = "") -> Finding:
    return Finding.build(
        rule_id, severity, message, evidence=evidence, references=POISONING_REFERENCES
    )


class McpFirewall:
    """Stateless inspector bound to one pin manifest."""

    def __init__(self, manifest: ToolManifest) -> None:
        self._manifest = manifest

    @property
    def manifest(self) -> ToolManifest:
        return self._manifest

    def inspect_tool(self, server_id: str, raw_tool: dict[str, Any]) -> ToolVerdict:
        """Scan one advertised tool and check it against its pin."""
        try:
            tool = McpTool.model_validate(raw_tool)
        except ValidationError as error:
            name = str(raw_tool.get("name", "<unnamed>"))
            malformed = _finding("AEGIS-FW-001", Severity.HIGH, "Malformed tool", str(error))
            return ToolVerdict(
                tool_name=name, allowed=False, pin_status="invalid", findings=[malformed]
            )
        findings = scan_tool(tool)
        status = self._manifest.verify(server_id, tool)
        if status is PinStatus.MUTATED:
            findings.append(
                _finding(
                    "AEGIS-FW-010",
                    Severity.CRITICAL,
                    "Tool definition changed after approval (rug pull)",
                    tool.name,
                )
            )
        elif status is PinStatus.UNPINNED:
            findings.append(
                _finding("AEGIS-FW-011", Severity.MEDIUM, "Tool has not been approved", tool.name)
            )
        clean = worst_severity(findings) < BLOCKING_SEVERITY
        allowed = clean and status is PinStatus.MATCH
        return ToolVerdict(
            tool_name=tool.name, allowed=allowed, pin_status=status.value, findings=findings
        )

    def inspect_tools_list(self, server_id: str, tools: list[dict[str, Any]]) -> ToolsListVerdict:
        """Filter a ``tools/list`` result down to tools safe to show the model."""
        verdicts = [self.inspect_tool(server_id, raw_tool) for raw_tool in tools]
        allowed_names = {verdict.tool_name for verdict in verdicts if verdict.allowed}
        allowed_tools = [tool for tool in tools if tool.get("name") in allowed_names]
        audit_event(
            "mcp.tools_list",
            server_id=server_id,
            allowed=sorted(allowed_names),
            blocked=[verdict.tool_name for verdict in verdicts if not verdict.allowed],
        )
        return ToolsListVerdict(server_id=server_id, allowed_tools=allowed_tools, verdicts=verdicts)

    def approve_tool(self, server_id: str, raw_tool: dict[str, Any], approved_by: str) -> str:
        """Pin a tool after human review. Poisoned tools cannot be approved."""
        tool = McpTool.model_validate(raw_tool)
        findings = scan_tool(tool)
        if worst_severity(findings) >= BLOCKING_SEVERITY:
            rule_ids = ", ".join(sorted({finding.rule_id for finding in findings}))
            raise PermissionError(f"refusing to pin poisoned tool {tool.name!r}: {rule_ids}")
        pinned = self._manifest.pin(server_id, tool, approved_by)
        audit_event("mcp.tool_pinned", server_id=server_id, tool=tool.name, sha256=pinned.sha256)
        return pinned.sha256

    def inspect_tools_call(
        self, server_id: str, call: ToolCall, advertised_tool: dict[str, Any]
    ) -> CallVerdict:
        """Validate a call against the pinned schema before it leaves the host."""
        verdict = self.inspect_tool(server_id, advertised_tool)
        findings = [f for f in verdict.findings if f.severity >= BLOCKING_SEVERITY]
        if verdict.tool_name != call.name:
            findings.append(
                _finding("AEGIS-FW-020", Severity.HIGH, "Call does not match tool", call.name)
            )
        elif verdict.allowed:
            schema = McpTool.model_validate(advertised_tool).input_schema
            findings.extend(_argument_findings(call, schema))
        elif not findings:
            findings.append(
                _finding("AEGIS-FW-011", Severity.HIGH, "Tool has not been approved", call.name)
            )
        allowed = not findings
        audit_event("mcp.tools_call", server_id=server_id, tool=call.name, allowed=allowed)
        return CallVerdict(tool_name=call.name, allowed=allowed, findings=findings)

    def inspect_tool_result(self, tool_name: str, result: Any) -> CallVerdict:
        """Scan tool output before it is appended to the model context."""
        findings = scan_tool_result(result)
        allowed = worst_severity(findings) < BLOCKING_SEVERITY
        audit_event("mcp.tool_result", tool=tool_name, allowed=allowed)
        return CallVerdict(tool_name=tool_name, allowed=allowed, findings=findings)


def _argument_findings(call: ToolCall, schema: dict[str, Any]) -> list[Finding]:
    """Schema-validate arguments and reject undeclared or sensitive values."""
    findings: list[Finding] = []
    # Undeclared arguments are how a poisoned prompt smuggles data out through
    # a tool whose schema looked harmless, so the schema is treated as closed.
    declared = set(schema.get("properties", {}))
    for name in sorted(set(call.arguments) - declared):
        findings.append(
            _finding("AEGIS-FW-021", Severity.HIGH, "Argument not declared in pinned schema", name)
        )
    try:
        validator = Draft202012Validator(schema)
        Draft202012Validator.check_schema(schema)
        errors = sorted(validator.iter_errors(call.arguments), key=lambda e: list(e.path))
    except SchemaError as schema_error:
        return [
            _finding(
                "AEGIS-FW-023", Severity.HIGH, "Pinned schema is invalid", schema_error.message
            )
        ]
    for violation in errors[:MAX_ARGUMENT_ERRORS_REPORTED]:
        findings.append(
            _finding("AEGIS-FW-022", Severity.HIGH, "Argument violates schema", violation.message)
        )
    for name, value in call.arguments.items():
        for text in iter_strings(value):
            findings.extend(
                f for f in scan_text(text, f"arguments/{name}") if f.rule_id == "AEGIS-TP-010"
            )
    return findings
