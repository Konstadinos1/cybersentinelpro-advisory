"""CI/CD red-team suite: a regression corpus of attacks run against the guards."""

from aegis.redteam.models import AttackCase, CaseResult, Expectation, Outcome, SuiteReport
from aegis.redteam.report import RENDERERS, to_json, to_junit, to_markdown
from aegis.redteam.runner import CorpusError, load_corpus, run_case, run_suite

__all__ = [
    "RENDERERS",
    "AttackCase",
    "CaseResult",
    "CorpusError",
    "Expectation",
    "Outcome",
    "SuiteReport",
    "load_corpus",
    "run_case",
    "run_suite",
    "to_json",
    "to_junit",
    "to_markdown",
]
