from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jwt
import pytest

from aegis.agency_guard import (
    AgencyGuard,
    ApprovalError,
    ApprovalGate,
    CircuitBreaker,
    CircuitOpenError,
    IdentityError,
    IdentityVerifier,
    Impact,
    Policy,
    PolicyEngine,
    RoleGrant,
    RunBudget,
    StepUsage,
    ToolRule,
    TripReason,
    call_digest,
    load_policy,
    sign_approval,
)
from aegis.core.findings import Decision
from tests.conftest import identity

SECRET = "s" * 64
APPROVAL_KEY = b"a" * 32
ISSUER = "https://idp.example.com"
AUDIENCE = "aegis-mcp"


def _token(secret: str = SECRET, algorithm: str = "HS256", **overrides: Any) -> str:
    now = datetime.now(UTC)
    claims: dict[str, Any] = {
        "sub": "alice",
        "tenant_id": "tenant-acme",
        "roles": ["viewer"],
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + timedelta(minutes=5),
    }
    claims.update(overrides)
    claims = {key: value for key, value in claims.items() if value is not None}
    return jwt.encode(claims, secret, algorithm=algorithm)


@pytest.fixture
def verifier() -> IdentityVerifier:
    return IdentityVerifier(SECRET, issuer=ISSUER, audience=AUDIENCE)


POLICY = Policy(
    tools=(
        ToolRule(pattern="search_*", impact=Impact.LOW),
        ToolRule(pattern="delete_*", impact=Impact.HIGH),
    ),
    roles={
        "viewer": RoleGrant(allow=("search_*",)),
        "operator": RoleGrant(allow=("search_*", "delete_*")),
        "contractor": RoleGrant(allow=("*",), deny=("delete_*",)),
    },
)


# ----------------------------------------------------------------- identity


def test_valid_token_yields_identity(verifier: IdentityVerifier) -> None:
    user = verifier.verify(_token())
    assert (user.subject, user.tenant_id, user.roles) == (
        "alice",
        "tenant-acme",
        frozenset({"viewer"}),
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"exp": datetime.now(UTC) - timedelta(hours=1)},
        {"aud": "another-service"},
        {"iss": "https://evil.example.net"},
        {"sub": None},
        {"exp": None},
        {"tenant_id": None},
        {"tenant_id": ""},
        {"roles": 7},
    ],
)
def test_bad_claims_are_rejected(verifier: IdentityVerifier, overrides: dict[str, Any]) -> None:
    with pytest.raises(IdentityError):
        verifier.verify(_token(**overrides))


def test_token_signed_with_other_key_is_rejected(verifier: IdentityVerifier) -> None:
    with pytest.raises(IdentityError):
        verifier.verify(_token(secret="x" * 40))


def test_unsigned_token_is_rejected(verifier: IdentityVerifier) -> None:
    with pytest.raises(IdentityError):
        verifier.verify(_token(secret="", algorithm="none"))


def test_other_hmac_algorithm_is_rejected(verifier: IdentityVerifier) -> None:
    with pytest.raises(IdentityError):
        verifier.verify(_token(algorithm="HS384"))


@pytest.mark.parametrize("garbage", ["", "abc", "a.b.c"])
def test_garbage_token_is_rejected(verifier: IdentityVerifier, garbage: str) -> None:
    with pytest.raises(IdentityError):
        verifier.verify(garbage)


def test_short_identity_secret_is_refused() -> None:
    with pytest.raises(ValueError, match="at least 32"):
        IdentityVerifier("short", issuer=ISSUER, audience=AUDIENCE)


# ------------------------------------------------------------------- policy


def test_low_impact_tool_is_allowed_for_granted_role() -> None:
    decision = PolicyEngine(POLICY).authorize(identity(roles=("viewer",)), "search_docs")
    assert decision.decision is Decision.ALLOW
    assert decision.matched_role == "viewer"


def test_confused_deputy_user_without_role_is_denied() -> None:
    decision = PolicyEngine(POLICY).authorize(identity(roles=("viewer",)), "delete_file")
    assert decision.decision is Decision.DENY


def test_high_impact_tool_requires_approval_even_when_granted() -> None:
    decision = PolicyEngine(POLICY).authorize(identity(roles=("operator",)), "delete_file")
    assert decision.decision is Decision.REQUIRE_APPROVAL


def test_deny_wins_over_allow_from_another_role() -> None:
    user = identity(roles=("operator", "contractor"))
    assert PolicyEngine(POLICY).authorize(user, "delete_file").decision is Decision.DENY


def test_unknown_tool_defaults_to_high_impact() -> None:
    decision = PolicyEngine(POLICY).authorize(identity(roles=("contractor",)), "brand_new_tool")
    assert decision.impact is Impact.HIGH
    assert decision.decision is Decision.REQUIRE_APPROVAL


@pytest.mark.parametrize("roles", [(), ("role-that-does-not-exist",)])
def test_no_matching_role_is_denied(roles: tuple[str, ...]) -> None:
    assert PolicyEngine(POLICY).authorize(identity(roles=roles), "search_docs").decision is (
        Decision.DENY
    )


def test_pattern_matching_is_case_sensitive() -> None:
    decision = PolicyEngine(POLICY).authorize(identity(roles=("viewer",)), "SEARCH_docs")
    assert decision.decision is Decision.DENY


def test_empty_policy_denies_everything() -> None:
    decision = PolicyEngine(Policy()).authorize(identity(roles=("admin",)), "anything")
    assert decision.decision is Decision.DENY


def test_policy_loads_from_yaml(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(
        "tools:\n  - {pattern: 'get_*', impact: low}\nroles:\n  reader:\n    allow: ['get_*']\n"
    )
    engine = PolicyEngine(load_policy(path))
    assert engine.authorize(identity(roles=("reader",)), "get_user").decision is Decision.ALLOW


# --------------------------------------------------------------------- HITL

ARGS = {"path": "tmp/cache.bin"}


def _gate(ttl: timedelta = timedelta(minutes=5)) -> ApprovalGate:
    return ApprovalGate(APPROVAL_KEY, ttl)


def test_signed_approval_allows_exactly_one_execution() -> None:
    gate = _gate()
    challenge = gate.create_challenge("alice", "delete_file", ARGS)
    signature = sign_approval(APPROVAL_KEY, challenge, "bob", "approve")
    assert gate.submit(challenge.challenge_id, "bob", "approve", signature) is True
    assert gate.consume_approval("alice", "delete_file", ARGS) is True
    assert gate.consume_approval("alice", "delete_file", ARGS) is False


def test_approval_is_bound_to_exact_arguments() -> None:
    gate = _gate()
    challenge = gate.create_challenge("alice", "delete_file", ARGS)
    signature = sign_approval(APPROVAL_KEY, challenge, "bob", "approve")
    gate.submit(challenge.challenge_id, "bob", "approve", signature)
    assert gate.consume_approval("alice", "delete_file", {"path": "/"}) is False


def test_approval_is_bound_to_the_requesting_user() -> None:
    gate = _gate()
    challenge = gate.create_challenge("alice", "delete_file", ARGS)
    signature = sign_approval(APPROVAL_KEY, challenge, "bob", "approve")
    gate.submit(challenge.challenge_id, "bob", "approve", signature)
    assert gate.consume_approval("mallory", "delete_file", ARGS) is False


def test_two_users_requesting_the_same_call_get_independent_approvals() -> None:
    gate = _gate()
    for requester in ("alice", "dave"):
        challenge = gate.create_challenge(requester, "delete_file", ARGS)
        signature = sign_approval(APPROVAL_KEY, challenge, "bob", "approve")
        gate.submit(challenge.challenge_id, "bob", "approve", signature)
    assert gate.consume_approval("alice", "delete_file", ARGS) is True
    assert gate.consume_approval("dave", "delete_file", ARGS) is True
    assert gate.consume_approval("dave", "delete_file", ARGS) is False


def test_abandoned_expired_challenges_are_purged() -> None:
    gate = _gate(ttl=timedelta(seconds=-1))
    stale = gate.create_challenge("alice", "delete_file", ARGS)
    gate.create_challenge("alice", "delete_file", {"path": "tmp/other"})
    assert gate.get_challenge(stale.challenge_id) is None


def test_rejection_does_not_grant_approval() -> None:
    gate = _gate()
    challenge = gate.create_challenge("alice", "delete_file", ARGS)
    signature = sign_approval(APPROVAL_KEY, challenge, "bob", "reject")
    assert gate.submit(challenge.challenge_id, "bob", "reject", signature) is False
    assert gate.consume_approval("alice", "delete_file", ARGS) is False


def test_signature_for_reject_cannot_be_used_to_approve() -> None:
    gate = _gate()
    challenge = gate.create_challenge("alice", "delete_file", ARGS)
    signature = sign_approval(APPROVAL_KEY, challenge, "bob", "reject")
    with pytest.raises(ApprovalError, match="signature"):
        gate.submit(challenge.challenge_id, "bob", "approve", signature)


def test_forged_signature_is_rejected_and_challenge_is_burned() -> None:
    gate = _gate()
    challenge = gate.create_challenge("alice", "delete_file", ARGS)
    forged = sign_approval(b"z" * 32, challenge, "bob", "approve")
    with pytest.raises(ApprovalError, match="signature"):
        gate.submit(challenge.challenge_id, "bob", "approve", forged)
    genuine = sign_approval(APPROVAL_KEY, challenge, "bob", "approve")
    with pytest.raises(ApprovalError, match="unknown or already used"):
        gate.submit(challenge.challenge_id, "bob", "approve", genuine)


def test_requester_cannot_approve_own_call() -> None:
    gate = _gate()
    challenge = gate.create_challenge("alice", "delete_file", ARGS)
    signature = sign_approval(APPROVAL_KEY, challenge, "alice", "approve")
    with pytest.raises(ApprovalError, match="own call"):
        gate.submit(challenge.challenge_id, "alice", "approve", signature)


def test_expired_challenge_is_rejected() -> None:
    gate = _gate(ttl=timedelta(seconds=-1))
    challenge = gate.create_challenge("alice", "delete_file", ARGS)
    signature = sign_approval(APPROVAL_KEY, challenge, "bob", "approve")
    with pytest.raises(ApprovalError, match="expired"):
        gate.submit(challenge.challenge_id, "bob", "approve", signature)


def test_unknown_challenge_and_invalid_verdict_are_rejected() -> None:
    gate = _gate()
    with pytest.raises(ApprovalError):
        gate.submit("nope", "bob", "approve", "0" * 64)
    challenge = gate.create_challenge("alice", "delete_file", ARGS)
    with pytest.raises(ApprovalError, match="verdict"):
        gate.submit(challenge.challenge_id, "bob", "maybe", "0" * 64)


def test_get_challenge_and_digest_helpers() -> None:
    gate = _gate()
    challenge = gate.create_challenge("alice", "delete_file", ARGS)
    assert gate.get_challenge(challenge.challenge_id) == challenge
    assert gate.get_challenge("missing") is None
    assert call_digest("t", {"a": 1, "b": 2}) == call_digest("t", {"b": 2, "a": 1})
    assert call_digest("t", {"a": 1}) != call_digest("t", {"a": 2})


def test_short_approval_key_is_refused() -> None:
    with pytest.raises(ValueError, match="at least 32"):
        ApprovalGate(b"short")


# ----------------------------------------------------------- circuit breaker


def _step(query: str = "q", **kwargs: Any) -> StepUsage:
    return StepUsage(tool_name="search_docs", arguments={"q": query}, **kwargs)


def test_run_within_budget_is_not_tripped() -> None:
    breaker = CircuitBreaker(RunBudget(max_steps=5))
    for index in range(5):
        breaker.record_step("run", _step(str(index)))
    assert not breaker.is_open("run")
    assert not breaker.is_open("never-seen")


def test_step_limit_trips_on_first_step_over() -> None:
    breaker = CircuitBreaker(RunBudget(max_steps=3))
    for index in range(3):
        breaker.record_step("run", _step(str(index)))
    with pytest.raises(CircuitOpenError) as caught:
        breaker.record_step("run", _step("3"))
    assert caught.value.reason is TripReason.STEP_LIMIT


def test_identical_state_loop_is_detected() -> None:
    breaker = CircuitBreaker(RunBudget(max_identical_states=2))
    breaker.record_step("run", _step())
    breaker.record_step("run", _step())
    with pytest.raises(CircuitOpenError) as caught:
        breaker.record_step("run", _step())
    assert caught.value.reason is TripReason.LOOP_DETECTED


def test_same_call_with_new_observation_is_progress_not_a_loop() -> None:
    breaker = CircuitBreaker(RunBudget(max_identical_states=1))
    breaker.record_step("run", _step(observation_digest="page-1"))
    breaker.record_step("run", _step(observation_digest="page-2"))
    assert not breaker.is_open("run")


@pytest.mark.parametrize(
    ("step_kwargs", "reason"),
    [
        ({"recursion_depth": 4}, TripReason.RECURSION_DEPTH),
        ({"tokens": 200_001}, TripReason.TOKEN_BUDGET),
        ({"cost_usd": 5.01}, TripReason.COST_BUDGET),
    ],
)
def test_single_step_over_a_ceiling_trips(step_kwargs: dict[str, Any], reason: TripReason) -> None:
    with pytest.raises(CircuitOpenError) as caught:
        CircuitBreaker(RunBudget()).record_step("run", _step(**step_kwargs))
    assert caught.value.reason is reason


def test_value_exactly_at_ceiling_is_allowed() -> None:
    breaker = CircuitBreaker(RunBudget())
    breaker.record_step("run", _step(recursion_depth=3, tokens=200_000, cost_usd=5.0))
    assert not breaker.is_open("run")


def test_tripped_breaker_stays_open_and_runs_are_independent() -> None:
    breaker = CircuitBreaker(RunBudget(max_steps=1))
    breaker.record_step("run-a", _step("1"))
    with pytest.raises(CircuitOpenError):
        breaker.record_step("run-a", _step("2"))
    with pytest.raises(CircuitOpenError):
        breaker.record_step("run-a", _step("3"))
    breaker.record_step("run-b", _step("1"))
    assert breaker.is_open("run-a") and not breaker.is_open("run-b")


@pytest.mark.parametrize("field", ["max_steps", "max_total_tokens", "max_cost_usd"])
def test_non_positive_budget_is_invalid(field: str) -> None:
    with pytest.raises(ValueError, match="greater than"):
        RunBudget(**{field: 0})


# -------------------------------------------------------------------- guard


def _guard(verifier: IdentityVerifier, budget: RunBudget | None = None) -> AgencyGuard:
    return AgencyGuard(
        verifier,
        PolicyEngine(POLICY),
        CircuitBreaker(budget or RunBudget()),
        ApprovalGate(APPROVAL_KEY),
    )


def test_guard_allows_low_impact_call(verifier: IdentityVerifier) -> None:
    decision = _guard(verifier).evaluate(_token(), "run", _step())
    assert decision.decision is Decision.ALLOW
    assert decision.subject == "alice"


def test_guard_denies_invalid_token_before_anything_else(verifier: IdentityVerifier) -> None:
    decision = _guard(verifier).evaluate("garbage", "run", _step())
    assert decision.decision is Decision.DENY
    assert decision.subject == ""


def test_guard_full_approval_flow(verifier: IdentityVerifier) -> None:
    guard = _guard(verifier)
    token = _token(roles=["operator"])
    step = StepUsage(tool_name="delete_file", arguments=ARGS)
    first = guard.evaluate(token, "run", step)
    assert first.decision is Decision.REQUIRE_APPROVAL
    assert first.challenge is not None
    signature = sign_approval(APPROVAL_KEY, first.challenge, "bob", "approve")
    guard.approvals.submit(first.challenge.challenge_id, "bob", "approve", signature)
    assert guard.evaluate(token, "run", step).decision is Decision.ALLOW
    assert guard.evaluate(token, "run", step).decision is Decision.REQUIRE_APPROVAL


def test_guard_denies_once_circuit_is_open(verifier: IdentityVerifier) -> None:
    guard = _guard(verifier, RunBudget(max_steps=1))
    assert guard.evaluate(_token(), "run", _step("1")).decision is Decision.ALLOW
    tripped = guard.evaluate(_token(), "run", _step("2"))
    assert tripped.decision is Decision.DENY
    assert "circuit open" in tripped.reason
