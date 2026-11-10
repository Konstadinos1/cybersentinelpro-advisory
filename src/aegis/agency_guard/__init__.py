"""Least-agency policy engine, approval gate and circuit breakers."""

from aegis.agency_guard.circuit_breaker import (
    CircuitBreaker,
    CircuitOpenError,
    RunBudget,
    StepUsage,
    TripReason,
)
from aegis.agency_guard.guard import AgencyGuard, GuardDecision
from aegis.agency_guard.hitl import (
    ApprovalChallenge,
    ApprovalError,
    ApprovalGate,
    call_digest,
    sign_approval,
)
from aegis.agency_guard.identity import IdentityError, IdentityVerifier, UserIdentity
from aegis.agency_guard.policy import (
    AuthorizationDecision,
    Impact,
    Policy,
    PolicyEngine,
    RoleGrant,
    ToolRule,
    load_policy,
)

__all__ = [
    "AgencyGuard",
    "ApprovalChallenge",
    "ApprovalError",
    "ApprovalGate",
    "AuthorizationDecision",
    "CircuitBreaker",
    "CircuitOpenError",
    "GuardDecision",
    "IdentityError",
    "IdentityVerifier",
    "Impact",
    "Policy",
    "PolicyEngine",
    "RoleGrant",
    "RunBudget",
    "StepUsage",
    "ToolRule",
    "TripReason",
    "UserIdentity",
    "call_digest",
    "load_policy",
    "sign_approval",
]
