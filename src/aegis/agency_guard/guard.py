"""Out-of-band authorisation proxy: every tool call passes through here."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from aegis.agency_guard.circuit_breaker import CircuitBreaker, CircuitOpenError, StepUsage
from aegis.agency_guard.hitl import ApprovalChallenge, ApprovalGate
from aegis.agency_guard.identity import IdentityError, IdentityVerifier
from aegis.agency_guard.policy import PolicyEngine
from aegis.core.audit import audit_event
from aegis.core.findings import Decision


class GuardDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    decision: Decision
    reason: str
    subject: str = ""
    challenge: ApprovalChallenge | None = None


class AgencyGuard:
    """Composes identity, RBAC, circuit breakers and the approval gate.

    Order matters: identity first (who), then budget (is the run still
    healthy), then policy (may they), then approval (did a human agree).
    """

    def __init__(
        self,
        verifier: IdentityVerifier,
        policy: PolicyEngine,
        breaker: CircuitBreaker,
        approvals: ApprovalGate,
    ) -> None:
        self._verifier = verifier
        self._policy = policy
        self._breaker = breaker
        self._approvals = approvals

    @property
    def approvals(self) -> ApprovalGate:
        return self._approvals

    def evaluate(self, user_token: str, run_id: str, step: StepUsage) -> GuardDecision:
        """Decide whether ``step`` may execute on behalf of the token's user."""
        decision = self._evaluate(user_token, run_id, step)
        audit_event(
            "agency.decision",
            run_id=run_id,
            tool=step.tool_name,
            subject=decision.subject,
            decision=decision.decision.value,
            reason=decision.reason,
        )
        return decision

    def _evaluate(self, user_token: str, run_id: str, step: StepUsage) -> GuardDecision:
        try:
            identity = self._verifier.verify(user_token)
        except IdentityError as error:
            return GuardDecision(decision=Decision.DENY, reason=str(error))
        try:
            self._breaker.record_step(run_id, step)
        except CircuitOpenError as error:
            return GuardDecision(
                decision=Decision.DENY,
                reason=f"circuit open ({error})",
                subject=identity.subject,
            )
        authorization = self._policy.authorize(identity, step.tool_name)
        if authorization.decision is not Decision.REQUIRE_APPROVAL:
            return GuardDecision(
                decision=authorization.decision,
                reason=authorization.reason,
                subject=identity.subject,
            )
        if self._approvals.consume_approval(identity.subject, step.tool_name, step.arguments):
            return GuardDecision(
                decision=Decision.ALLOW,
                reason="high-impact call approved by a human",
                subject=identity.subject,
            )
        challenge = self._approvals.create_challenge(
            identity.subject, step.tool_name, step.arguments
        )
        return GuardDecision(
            decision=Decision.REQUIRE_APPROVAL,
            reason="high-impact call requires human approval",
            subject=identity.subject,
            challenge=challenge,
        )
