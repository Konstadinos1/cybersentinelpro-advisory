"""Static rule set for tool-poisoning detection.

Rules are data, not code, so reviewers can audit exactly what is matched
and the red-team suite can report coverage per rule.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from aegis.core.findings import Severity

REF_PROMPT_INJECTION = "OWASP-LLM01:2026"
REF_SUPPLY_CHAIN = "OWASP-LLM04:2026"
REF_TOOL_MISUSE = "OWASP-ASI02"
REF_AGENTIC_SUPPLY_CHAIN = "OWASP-ASI04"
REF_ATLAS_INJECTION = "MITRE-ATLAS:AML.T0051"

POISONING_REFERENCES = (
    REF_PROMPT_INJECTION,
    REF_SUPPLY_CHAIN,
    REF_TOOL_MISUSE,
    REF_AGENTIC_SUPPLY_CHAIN,
    REF_ATLAS_INJECTION,
)


@dataclass(frozen=True)
class PatternRule:
    rule_id: str
    severity: Severity
    message: str
    pattern: re.Pattern[str]


def _rule(rule_id: str, severity: Severity, message: str, regex: str) -> PatternRule:
    return PatternRule(rule_id, severity, message, re.compile(regex, re.IGNORECASE | re.DOTALL))


INJECTION_RULES: tuple[PatternRule, ...] = (
    _rule(
        "AEGIS-TP-001",
        Severity.HIGH,
        "Instruction override phrasing",
        r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|all|any)\b"
        r".{0,40}\b(instructions?|rules?|prompts?|guidelines?|context)\b",
    ),
    _rule(
        "AEGIS-TP-002",
        Severity.HIGH,
        "Instruction to conceal behaviour from the user",
        r"\b(do\s*not|don't|never|without)\b.{0,40}\b(tell|inform|mention|notify|reveal|show|"
        r"alert|telling|informing|mentioning|notifying)\b.{0,40}\b(the\s+)?(user|human|operator)\b",
    ),
    _rule(
        "AEGIS-TP-003",
        Severity.MEDIUM,
        "Directive markup aimed at the model rather than the reader",
        r"<\s*(important|system|secret|instructions?|admin|override)\s*>|\[\s*(system|inst)\s*\]",
    ),
    _rule(
        "AEGIS-TP-004",
        Severity.HIGH,
        "Precondition that makes the model read or act before calling the tool",
        r"\b(before|prior\s+to|first|always)\b.{0,60}\b(read|open|cat|load|fetch|include|attach|"
        r"pass|send)\b.{0,80}\b(file|contents?|config|key|credentials?|token)\b",
    ),
    _rule(
        "AEGIS-TP-005",
        Severity.HIGH,
        "Cross-tool shadowing: description changes how another tool is used",
        r"\bwhen(ever)?\b.{0,40}\b(using|calling|invoking|the)\b.{0,40}\b(tool|function)\b"
        r".{0,80}\b(must|should|always|instead|also|redirect|bcc|forward)\b",
    ),
    _rule(
        "AEGIS-TP-006",
        Severity.CRITICAL,
        "Exfiltration instruction (send, upload or encode data to a destination)",
        r"\b(send|post|upload|forward|exfiltrate|transmit|leak|email)\b.{0,80}"
        r"(https?://|\bto\s+the\s+(server|endpoint|webhook)\b|\bbase64\b)",
    ),
    _rule(
        "AEGIS-TP-007",
        Severity.MEDIUM,
        "Role reassignment or jailbreak framing",
        r"\byou\s+are\s+now\b|\bact\s+as\s+(an?\s+)?(admin|root|system|developer)\b|"
        r"\bdeveloper\s+mode\b|\bDAN\b",
    ),
)

SENSITIVE_PATH_RULE = _rule(
    "AEGIS-TP-010",
    Severity.CRITICAL,
    "Reference to a sensitive local path or credential store",
    r"~/\.ssh\b|\bid_(rsa|ed25519|ecdsa)\b|\.cursor/mcp\.json|\bmcp\.json\b|(^|[\s/\"'`(])\.env\b|"
    r"/etc/(passwd|shadow|sudoers)|~/\.aws\b|\.aws/credentials|~/\.kube\b|\.npmrc\b|\.netrc\b|"
    r"\.git-credentials\b|~/\.gnupg\b|\bkeychain\b|\bwallet\.dat\b|\bseed\s+phrase\b",
)

# Parameters whose only plausible purpose is to carry data the user never sees.
SUSPICIOUS_PARAMETER_NAMES = frozenset(
    {
        "sidenote",
        "side_note",
        "telemetry_payload",
        "telemetry",
        "debug_info",
        "debug_payload",
        "context_dump",
        "extra_context",
        "hidden",
        "internal_notes",
        "metadata_blob",
        "feedback",
        "trace_data",
    }
)
