"""Agentic circuit breakers against unbounded consumption.

A token-draining ("Clawdrain") attack tricks an agent into looping: calling
tools that return content asking for more tool calls. Budgets are enforced
outside the model, per run, and a tripped breaker stays open.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from aegis.core.canonical import sha256_hex


class TripReason(StrEnum):
    STEP_LIMIT = "step_limit"
    RECURSION_DEPTH = "recursion_depth"
    LOOP_DETECTED = "loop_detected"
    TOKEN_BUDGET = "token_budget"  # noqa: S105 - a reason code, not a credential
    COST_BUDGET = "cost_budget"


class RunBudget(BaseModel):
    """Ceilings for a single agent run."""

    model_config = ConfigDict(frozen=True)

    max_steps: int = Field(default=25, gt=0)
    max_recursion_depth: int = Field(default=3, ge=0)
    max_total_tokens: int = Field(default=200_000, gt=0)
    max_cost_usd: float = Field(default=5.0, gt=0)
    # How many times the same state may repeat before it is called a loop.
    max_identical_states: int = Field(default=3, gt=0)


class StepUsage(BaseModel):
    """What one agent step consumed and where it was in the call tree."""

    model_config = ConfigDict(frozen=True)

    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    observation_digest: str = ""
    recursion_depth: int = Field(default=0, ge=0)
    tokens: int = Field(default=0, ge=0)
    cost_usd: float = Field(default=0.0, ge=0)


class CircuitOpenError(Exception):
    """Raised when a run exceeds its budget; the run must be terminated."""

    def __init__(self, reason: TripReason, detail: str) -> None:
        super().__init__(f"{reason.value}: {detail}")
        self.reason = reason
        self.detail = detail


@dataclass
class _RunState:
    steps: int = 0
    tokens: int = 0
    cost_usd: float = 0.0
    state_hashes: Counter[str] = field(default_factory=Counter)
    tripped: CircuitOpenError | None = None


def state_hash(step: StepUsage) -> str:
    """Hash of what the agent did and saw; equal hashes mean no progress."""
    return sha256_hex(
        {
            "tool": step.tool_name,
            "arguments": step.arguments,
            "observation": step.observation_digest,
        }
    )


class CircuitBreaker:
    """Tracks consumption per run id and trips on the first exceeded limit."""

    def __init__(self, budget: RunBudget) -> None:
        self._budget = budget
        self._runs: dict[str, _RunState] = {}

    def record_step(self, run_id: str, step: StepUsage) -> None:
        """Account for a step *before* it executes; raise if the run must stop."""
        state = self._runs.setdefault(run_id, _RunState())
        if state.tripped is not None:
            raise state.tripped
        state.steps += 1
        state.tokens += step.tokens
        state.cost_usd += step.cost_usd
        state.state_hashes[state_hash(step)] += 1
        violation = self._first_violation(state, step)
        if violation is not None:
            state.tripped = violation
            raise violation

    def is_open(self, run_id: str) -> bool:
        state = self._runs.get(run_id)
        return state is not None and state.tripped is not None

    def _first_violation(self, state: _RunState, step: StepUsage) -> CircuitOpenError | None:
        budget = self._budget
        repeats = state.state_hashes[state_hash(step)]
        checks: tuple[tuple[bool, TripReason, str], ...] = (
            (
                step.recursion_depth > budget.max_recursion_depth,
                TripReason.RECURSION_DEPTH,
                f"depth {step.recursion_depth} > {budget.max_recursion_depth}",
            ),
            (
                repeats > budget.max_identical_states,
                TripReason.LOOP_DETECTED,
                f"state repeated {repeats} times",
            ),
            (
                state.steps > budget.max_steps,
                TripReason.STEP_LIMIT,
                f"step {state.steps} > {budget.max_steps}",
            ),
            (
                state.tokens > budget.max_total_tokens,
                TripReason.TOKEN_BUDGET,
                f"{state.tokens} tokens > {budget.max_total_tokens}",
            ),
            (
                state.cost_usd > budget.max_cost_usd,
                TripReason.COST_BUDGET,
                f"${state.cost_usd:.2f} > ${budget.max_cost_usd:.2f}",
            ),
        )
        for exceeded, reason, detail in checks:
            if exceeded:
                return CircuitOpenError(reason, detail)
        return None
