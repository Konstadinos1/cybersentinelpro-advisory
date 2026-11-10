"""Append-only structured audit log.

Decisions are logged as single-line JSON so they can be shipped to a SIEM
without parsing. Free-text fields are passed through the DLP redactor by
the callers before they reach this module.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

AUDIT_LOGGER_NAME = "aegis.audit"

_logger = logging.getLogger(AUDIT_LOGGER_NAME)


def audit_event(event: str, **fields: Any) -> dict[str, Any]:
    """Emit one audit record and return it (handy for tests and API responses)."""
    record: dict[str, Any] = {
        "ts": datetime.now(UTC).isoformat(),
        "event": event,
        **fields,
    }
    _logger.info(json.dumps(record, sort_keys=True, default=str))
    return record
