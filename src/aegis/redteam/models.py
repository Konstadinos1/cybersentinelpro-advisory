"""Data model for red-team cases and results."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Expectation(StrEnum):
    """What the guard must do for the case to pass."""

    BLOCKED = "blocked"  # an attack: the control must stop it
    ALLOWED = "allowed"  # a benign control: the guard must not interfere


class AttackCase(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    title: str
    module: str
    kind: str
    expect: Expectation
    description: str = ""
    references: tuple[str, ...] = ()
    input: dict[str, Any] = Field(default_factory=dict)


class Outcome(BaseModel):
    """What actually happened when the case ran against the guards."""

    blocked: bool
    detail: str
    rule_ids: tuple[str, ...] = ()


class CaseResult(BaseModel):
    case: AttackCase
    outcome: Outcome
    passed: bool


class SuiteReport(BaseModel):
    results: list[CaseResult]

    @property
    def failures(self) -> list[CaseResult]:
        return [result for result in self.results if not result.passed]

    def _rate(self, expectation: Expectation) -> float:
        relevant = [r for r in self.results if r.case.expect is expectation]
        if not relevant:
            return 1.0
        return sum(r.passed for r in relevant) / len(relevant)

    @property
    def attack_block_rate(self) -> float:
        """Share of attacks stopped."""
        return self._rate(Expectation.BLOCKED)

    @property
    def benign_pass_rate(self) -> float:
        """Share of legitimate requests left alone (1 - false positive rate)."""
        return self._rate(Expectation.ALLOWED)
