"""Detectors for secrets and personal data.

Each detector is a regex plus an optional validator. Validators (Luhn for
card and SIN numbers) keep false positives low enough that redaction can
run on every response without mangling ordinary text.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from aegis.core.findings import Severity

CARD_MIN_DIGITS = 13
CARD_MAX_DIGITS = 19
SIN_DIGITS = 9
IBAN_MIN_CHARS = 15
IBAN_MAX_CHARS = 34
LUHN_DOUBLE_OVERFLOW = 9


def luhn_valid(digits: str) -> bool:
    """Luhn checksum used by payment cards and Canadian SINs."""
    total = 0
    for index, character in enumerate(reversed(digits)):
        value = int(character)
        if index % 2 == 1:
            value *= 2
            if value > LUHN_DOUBLE_OVERFLOW:
                value -= LUHN_DOUBLE_OVERFLOW
        total += value
    return total % 10 == 0


def _digits_only(text: str) -> str:
    return re.sub(r"\D", "", text)


def _valid_card(match_text: str) -> bool:
    digits = _digits_only(match_text)
    return CARD_MIN_DIGITS <= len(digits) <= CARD_MAX_DIGITS and luhn_valid(digits)


def _valid_sin(match_text: str) -> bool:
    digits = _digits_only(match_text)
    return len(digits) == SIN_DIGITS and luhn_valid(digits)


def _valid_us_ssn(match_text: str) -> bool:
    """Reject number ranges the SSA never issues, which are common in dummy data."""
    area, group, serial = match_text.split("-")
    return (
        area not in ("000", "666")
        and not area.startswith("9")
        and group != "00"
        and serial != "0000"
    )


def iban_valid(candidate: str) -> bool:
    """ISO 13616 mod-97 check: move four characters to the end, map A=10..Z=35."""
    compact = re.sub(r"\s", "", candidate).upper()
    if not IBAN_MIN_CHARS <= len(compact) <= IBAN_MAX_CHARS or not compact.isalnum():
        return False
    rearranged = compact[4:] + compact[:4]
    return int("".join(str(int(character, 36)) for character in rearranged)) % 97 == 1


@dataclass(frozen=True)
class Detector:
    label: str
    severity: Severity
    pattern: re.Pattern[str]
    # Group to redact; 0 means the whole match.
    group: int = 0
    validator: Callable[[str], bool] | None = None


def _detector(
    label: str,
    severity: Severity,
    regex: str,
    *,
    group: int = 0,
    validator: Callable[[str], bool] | None = None,
    flags: int = 0,
) -> Detector:
    return Detector(label, severity, re.compile(regex, flags), group, validator)


SECRET_DETECTORS: tuple[Detector, ...] = (
    _detector(
        "PRIVATE_KEY",
        Severity.CRITICAL,
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)",
        flags=re.DOTALL,
    ),
    _detector("AWS_ACCESS_KEY", Severity.CRITICAL, r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    _detector("GITHUB_TOKEN", Severity.CRITICAL, r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    _detector("GITHUB_TOKEN", Severity.CRITICAL, r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
    _detector("LLM_API_KEY", Severity.CRITICAL, r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}"),
    _detector("SLACK_TOKEN", Severity.CRITICAL, r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    _detector("STRIPE_KEY", Severity.CRITICAL, r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}"),
    # Google API keys have no checksum, so any string of this shape is treated
    # as one. That is also why none may appear literally in this repository.
    _detector("GOOGLE_API_KEY", Severity.CRITICAL, r"\bAIza[0-9A-Za-z_-]{35}\b"),
    _detector(
        "AWS_SECRET_KEY",
        Severity.CRITICAL,
        r"\baws.{0,40}?[\"']?([0-9A-Za-z/+]{40})(?![0-9A-Za-z/+])",
        group=1,
        flags=re.IGNORECASE,
    ),
    _detector(
        "BEARER_TOKEN",
        Severity.HIGH,
        r"\bauthorization\b[\"'\s:]{0,4}bearer\s+([A-Za-z0-9._-]{10,})",
        group=1,
        flags=re.IGNORECASE,
    ),
    _detector("ETH_PRIVATE_KEY", Severity.CRITICAL, r"\b0x[a-fA-F0-9]{64}\b"),
    _detector(
        "JWT",
        Severity.HIGH,
        r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
    ),
    _detector(
        "CREDENTIAL_ASSIGNMENT",
        Severity.HIGH,
        r"\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b"
        r"\s*[:=]\s*[\"']?([^\s\"',;]{8,})",
        group=1,
        flags=re.IGNORECASE,
    ),
)

PII_DETECTORS: tuple[Detector, ...] = (
    _detector("EMAIL", Severity.MEDIUM, r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    _detector(
        "PAYMENT_CARD",
        Severity.HIGH,
        r"\b\d(?:[ -]?\d){12,18}\b",
        validator=_valid_card,
    ),
    _detector(
        "CANADIAN_SIN",
        Severity.HIGH,
        r"\b\d{3}[ -]?\d{3}[ -]?\d{3}\b",
        validator=_valid_sin,
    ),
    _detector("US_SSN", Severity.HIGH, r"\b\d{3}-\d{2}-\d{4}\b", validator=_valid_us_ssn),
    _detector(
        "IBAN",
        Severity.HIGH,
        r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b",
        validator=iban_valid,
    ),
    _detector(
        "PHONE_NUMBER",
        Severity.MEDIUM,
        r"(?<![\w.])(?:\+?1[ .-]?)?\(?[2-9]\d{2}\)?[ .-]\d{3}[ .-]\d{4}\b",
    ),
)
