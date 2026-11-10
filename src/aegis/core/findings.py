"""Finding and decision types shared by all guards.

Every control returns structured findings rather than booleans so that the
audit trail and the red-team report can explain *why* something was blocked.
"""

from __future__ import annotations

from enum import IntEnum, StrEnum

from pydantic import BaseModel, ConfigDict, Field

EVIDENCE_MAX_CHARS = 160


class Severity(IntEnum):
    """Ordered so that ``max()`` yields the most severe finding."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class Finding(BaseModel):
    """One reason a control flagged an input."""

    model_config = ConfigDict(frozen=True)

    rule_id: str
    severity: Severity
    message: str
    location: str = ""
    evidence: str = ""
    references: tuple[str, ...] = Field(default_factory=tuple)

    @classmethod
    def build(
        cls,
        rule_id: str,
        severity: Severity,
        message: str,
        *,
        location: str = "",
        evidence: str = "",
        references: tuple[str, ...] = (),
    ) -> Finding:
        """Create a finding with evidence truncated so logs stay bounded."""
        return cls(
            rule_id=rule_id,
            severity=severity,
            message=message,
            location=location,
            evidence=evidence[:EVIDENCE_MAX_CHARS],
            references=references,
        )


def worst_severity(findings: list[Finding]) -> Severity:
    """Return the highest severity present, or INFO for an empty list."""
    return max((finding.severity for finding in findings), default=Severity.INFO)
