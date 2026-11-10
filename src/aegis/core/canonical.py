"""Canonical JSON serialisation and hashing.

Hashes are only comparable if the bytes are stable, so every digest in the
project goes through this one function. Text is deliberately NOT Unicode
normalised: a tool description that gains a zero-width character must
produce a different hash.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> bytes:
    """Serialise ``value`` deterministically (sorted keys, no whitespace)."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def sha256_hex(value: Any) -> str:
    """SHA-256 hex digest of the canonical JSON form of ``value``."""
    return hashlib.sha256(canonical_json(value)).hexdigest()
