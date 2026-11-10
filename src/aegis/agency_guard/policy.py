"""Deterministic, default-deny RBAC policy for tool calls.

The policy is plain data loaded from YAML. There is no model in the
decision path, so a prompt injection cannot argue its way to a permission.
"""

from __future__ import annotations

from enum import StrEnum
from fnmatch import fnmatchcase
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

from aegis.agency_guard.identity import UserIdentity
from aegis.core.findings import Decision


class Impact(StrEnum):
    """How much damage a tool can do if misused."""

    LOW = "low"
    HIGH = "high"


class ToolRule(BaseModel):
    """Classification of a tool (or glob of tools)."""

    model_config = ConfigDict(frozen=True)

    pattern: str = Field(min_length=1)
    impact: Impact = Impact.LOW
    description: str = ""


class RoleGrant(BaseModel):
    model_config = ConfigDict(frozen=True)

    allow: tuple[str, ...] = ()
    deny: tuple[str, ...] = ()


class Policy(BaseModel):
    """Roles map to tool globs; tools map to an impact level."""

    version: int = 1
    tools: tuple[ToolRule, ...] = ()
    roles: dict[str, RoleGrant] = Field(default_factory=dict)
    # Unknown tools are treated as high impact: fail towards more oversight.
    default_impact: Impact = Impact.HIGH


class AuthorizationDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    decision: Decision
    reason: str
    impact: Impact
    matched_role: str = ""


def load_policy(path: Path) -> Policy:
    """Load and validate a policy file; ``safe_load`` prevents YAML code execution."""
    return Policy.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


def _matches_any(tool_name: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatchcase(tool_name, pattern) for pattern in patterns)


class PolicyEngine:
    """Answers one question: may this human invoke this tool?"""

    def __init__(self, policy: Policy) -> None:
        self._policy = policy

    def impact_of(self, tool_name: str) -> Impact:
        """First matching tool rule wins; unknown tools use the default."""
        for rule in self._policy.tools:
            if fnmatchcase(tool_name, rule.pattern):
                return rule.impact
        return self._policy.default_impact

    def authorize(self, identity: UserIdentity, tool_name: str) -> AuthorizationDecision:
        """Deny wins over allow; no matching allow means deny."""
        impact = self.impact_of(tool_name)
        granting_role = ""
        for role in sorted(identity.roles):
            grant = self._policy.roles.get(role)
            if grant is None:
                continue
            if _matches_any(tool_name, grant.deny):
                return AuthorizationDecision(
                    decision=Decision.DENY,
                    reason=f"role {role!r} explicitly denies {tool_name!r}",
                    impact=impact,
                    matched_role=role,
                )
            if not granting_role and _matches_any(tool_name, grant.allow):
                granting_role = role
        if not granting_role:
            return AuthorizationDecision(
                decision=Decision.DENY,
                reason=f"no role held by {identity.subject!r} grants {tool_name!r}",
                impact=impact,
            )
        decision = Decision.REQUIRE_APPROVAL if impact is Impact.HIGH else Decision.ALLOW
        return AuthorizationDecision(
            decision=decision,
            reason=f"granted by role {granting_role!r}",
            impact=impact,
            matched_role=granting_role,
        )
