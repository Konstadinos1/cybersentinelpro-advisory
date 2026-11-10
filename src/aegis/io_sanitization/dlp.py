"""Egress DLP and reasoning-trace redaction.

Applied to final responses AND to intermediate reasoning before anything is
logged or returned. Reasoning traces matter because models often restate
the system prompt or a credential while "thinking", and those traces end
up in observability tools with far weaker access control than production.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from pydantic import BaseModel, Field

from aegis.core.findings import Finding, Severity
from aegis.io_sanitization.detectors import PII_DETECTORS, SECRET_DETECTORS, Detector

REF_SENSITIVE_DISCLOSURE = "OWASP-LLM02:2026"
REF_HIDDEN_CONTEXT = "OWASP-LLM08:2026"
DLP_REFERENCES = (REF_SENSITIVE_DISCLOSURE, REF_HIDDEN_CONTEXT)

CANARY_MIN_CHARS = 8
REASONING_TAGS = ("thinking", "reasoning", "scratchpad", "think", "reflection")
REASONING_PLACEHOLDER = "[REASONING REMOVED]"

_REASONING_PATTERN = re.compile(
    r"<\s*(?P<tag>" + "|".join(REASONING_TAGS) + r")\b[^>]*>(?P<body>.*?)"
    # An unclosed tag swallows the rest of the text: fail closed.
    r"(?:<\s*/\s*(?P=tag)\s*>|\Z)",
    re.IGNORECASE | re.DOTALL,
)


class ReasoningMode(StrEnum):
    """What to do with reasoning traces."""

    DROP = "drop"
    REDACT = "redact"


class RedactionResult(BaseModel):
    text: str
    findings: list[Finding] = Field(default_factory=list)

    @property
    def redacted(self) -> bool:
        return bool(self.findings)


@dataclass(frozen=True)
class _Span:
    start: int
    end: int
    label: str
    severity: Severity


def _detector_spans(text: str, detector: Detector) -> list[_Span]:
    spans: list[_Span] = []
    for match in detector.pattern.finditer(text):
        if detector.validator is not None and not detector.validator(match.group(0)):
            continue
        start, end = match.span(detector.group)
        spans.append(_Span(start, end, detector.label, detector.severity))
    return spans


def _non_overlapping(spans: list[_Span]) -> list[_Span]:
    """Keep the earliest span; on a tie keep the longest."""
    kept: list[_Span] = []
    for span in sorted(spans, key=lambda s: (s.start, -(s.end - s.start))):
        if not kept or span.start >= kept[-1].end:
            kept.append(span)
    return kept


class DlpRedactor:
    """Redacts secrets, PII and system-prompt canaries from model output."""

    def __init__(self, canaries: tuple[str, ...] = (), *, redact_pii: bool = True) -> None:
        for canary in canaries:
            if len(canary) < CANARY_MIN_CHARS:
                raise ValueError(f"canary must be at least {CANARY_MIN_CHARS} characters")
        self._canaries = canaries
        self._detectors = SECRET_DETECTORS + (PII_DETECTORS if redact_pii else ())

    def _canary_spans(self, text: str) -> list[_Span]:
        spans: list[_Span] = []
        lowered = text.lower()
        for canary in self._canaries:
            start = lowered.find(canary.lower())
            while start != -1:
                spans.append(_Span(start, start + len(canary), "CANARY", Severity.CRITICAL))
                start = lowered.find(canary.lower(), start + 1)
        return spans

    def redact(self, text: str, location: str = "response") -> RedactionResult:
        """Replace every detected span with a typed placeholder."""
        spans = self._canary_spans(text)
        for detector in self._detectors:
            spans.extend(_detector_spans(text, detector))
        pieces: list[str] = []
        findings: list[Finding] = []
        cursor = 0
        for span in _non_overlapping(spans):
            pieces.append(text[cursor : span.start])
            pieces.append(f"[REDACTED:{span.label}]")
            cursor = span.end
            findings.append(
                Finding.build(
                    f"AEGIS-DLP-{span.label}",
                    span.severity,
                    f"{span.label} removed from {location}",
                    location=location,
                    references=DLP_REFERENCES,
                )
            )
        pieces.append(text[cursor:])
        return RedactionResult(text="".join(pieces), findings=findings)

    def sanitize_output(
        self, text: str, reasoning_mode: ReasoningMode = ReasoningMode.DROP
    ) -> RedactionResult:
        """Handle reasoning traces, then redact what remains."""
        findings: list[Finding] = []

        def replace(match: re.Match[str]) -> str:
            tag = match.group("tag").lower()
            if reasoning_mode is ReasoningMode.DROP:
                findings.append(
                    Finding.build(
                        "AEGIS-DLP-REASONING",
                        Severity.LOW,
                        "Reasoning trace removed",
                        location=tag,
                        references=DLP_REFERENCES,
                    )
                )
                return REASONING_PLACEHOLDER
            inner = self.redact(match.group("body"), location=tag)
            findings.extend(inner.findings)
            return f"<{tag}>{inner.text}</{tag}>"

        without_reasoning = _REASONING_PATTERN.sub(replace, text)
        result = self.redact(without_reasoning)
        return RedactionResult(text=result.text, findings=findings + result.findings)
