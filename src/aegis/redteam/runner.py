"""Loads the attack corpus and runs it against the real guards."""

from __future__ import annotations

from importlib import resources
from pathlib import Path

import yaml

from aegis.redteam.handlers import HANDLERS
from aegis.redteam.lab import build_lab_services, render
from aegis.redteam.models import AttackCase, CaseResult, Expectation, Outcome, SuiteReport


class CorpusError(Exception):
    """A corpus file is malformed or references an unknown case kind."""


def _parse_cases(text: str, origin: str) -> list[AttackCase]:
    try:
        raw_cases = yaml.safe_load(text) or []
        cases = [AttackCase.model_validate(raw) for raw in raw_cases]
    except (yaml.YAMLError, ValueError, TypeError) as error:
        raise CorpusError(f"invalid corpus file {origin}: {error}") from error
    for case in cases:
        if case.kind not in HANDLERS:
            raise CorpusError(f"{origin}: case {case.id} has unknown kind {case.kind!r}")
    return cases


def load_corpus(directory: Path | None = None) -> list[AttackCase]:
    """Load every ``*.yaml`` case file, from ``directory`` or the packaged corpus."""
    cases: list[AttackCase] = []
    if directory is None:
        root = resources.files("aegis.redteam").joinpath("corpus")
        files = sorted((f for f in root.iterdir() if f.name.endswith(".yaml")), key=str)
        for file in files:
            cases.extend(_parse_cases(file.read_text("utf-8"), file.name))
    else:
        for path in sorted(directory.glob("*.yaml")):
            cases.extend(_parse_cases(path.read_text(encoding="utf-8"), path.name))
    identifiers = [case.id for case in cases]
    duplicates = sorted({i for i in identifiers if identifiers.count(i) > 1})
    if duplicates:
        raise CorpusError(f"duplicate case ids: {', '.join(duplicates)}")
    return cases


def run_case(case: AttackCase) -> CaseResult:
    """Run one case in an isolated lab. A crash counts as a failed case."""
    try:
        outcome = HANDLERS[case.kind](build_lab_services(), render(case.input))
    except Exception as error:
        outcome = Outcome(blocked=False, detail=f"handler error: {type(error).__name__}: {error}")
        return CaseResult(case=case, outcome=outcome, passed=False)
    passed = outcome.blocked == (case.expect is Expectation.BLOCKED)
    return CaseResult(case=case, outcome=outcome, passed=passed)


def run_suite(cases: list[AttackCase]) -> SuiteReport:
    return SuiteReport(results=[run_case(case) for case in cases])
