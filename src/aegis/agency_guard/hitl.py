"""Human-in-the-loop approval gate for high-impact tool calls.

A challenge is bound to the exact call (tool name plus argument digest), so
an approval for ``delete_file(path="tmp/a")`` cannot be replayed for
``delete_file(path="/")``. Approvals are HMAC-signed by the approver's
channel (webhook or CLI), single-use, and expire quickly.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict

from aegis.core.canonical import sha256_hex

APPROVAL_KEY_MIN_BYTES = 32
DEFAULT_CHALLENGE_TTL = timedelta(minutes=5)
CHALLENGE_ID_BYTES = 16
SIGNATURE_VERSION = "v1"
APPROVE = "approve"
REJECT = "reject"


class ApprovalError(Exception):
    """The approval is invalid, expired, replayed, or does not match the call."""


class ApprovalChallenge(BaseModel):
    model_config = ConfigDict(frozen=True)

    challenge_id: str
    requested_by: str
    tool_name: str
    call_digest: str
    expires_at: datetime


def call_digest(tool_name: str, arguments: dict[str, Any]) -> str:
    """Digest that uniquely identifies one call, arguments included."""
    return sha256_hex({"tool": tool_name, "arguments": arguments})


def signing_payload(challenge: ApprovalChallenge, approver: str, verdict: str) -> bytes:
    """The exact bytes an approver signs. Every field is security relevant."""
    parts = (
        SIGNATURE_VERSION,
        challenge.challenge_id,
        challenge.call_digest,
        challenge.expires_at.isoformat(),
        approver,
        verdict,
    )
    return "\n".join(parts).encode("utf-8")


def sign_approval(key: bytes, challenge: ApprovalChallenge, approver: str, verdict: str) -> str:
    """Produce the signature an approval channel attaches to its response."""
    return hmac.new(key, signing_payload(challenge, approver, verdict), hashlib.sha256).hexdigest()


class ApprovalGate:
    """Issues challenges and verifies signed responses."""

    def __init__(self, key: bytes, ttl: timedelta = DEFAULT_CHALLENGE_TTL) -> None:
        if len(key) < APPROVAL_KEY_MIN_BYTES:
            raise ValueError(f"approval key must be at least {APPROVAL_KEY_MIN_BYTES} bytes")
        self._key = key
        self._ttl = ttl
        self._pending: dict[str, ApprovalChallenge] = {}
        # Keyed by (requester, call digest) so two users asking for the same
        # call never share, or overwrite, each other's approval.
        self._approved: set[tuple[str, str]] = set()

    def create_challenge(
        self, requested_by: str, tool_name: str, arguments: dict[str, Any]
    ) -> ApprovalChallenge:
        """Open a challenge for one specific call."""
        self._purge_expired()
        challenge = ApprovalChallenge(
            challenge_id=secrets.token_urlsafe(CHALLENGE_ID_BYTES),
            requested_by=requested_by,
            tool_name=tool_name,
            call_digest=call_digest(tool_name, arguments),
            expires_at=datetime.now(UTC) + self._ttl,
        )
        self._pending[challenge.challenge_id] = challenge
        return challenge

    def _purge_expired(self) -> None:
        """Drop abandoned challenges so the pending table cannot grow without bound."""
        now = datetime.now(UTC)
        for challenge_id in [cid for cid, c in self._pending.items() if now >= c.expires_at]:
            del self._pending[challenge_id]

    def get_challenge(self, challenge_id: str) -> ApprovalChallenge | None:
        return self._pending.get(challenge_id)

    def submit(self, challenge_id: str, approver: str, verdict: str, signature: str) -> bool:
        """Verify a signed response. Returns True when the call is approved.

        The challenge is consumed on first use, valid or not, so a signature
        cannot be brute-forced against the same challenge.
        """
        challenge = self._pending.pop(challenge_id, None)
        if challenge is None:
            raise ApprovalError("unknown or already used challenge")
        if verdict not in (APPROVE, REJECT):
            raise ApprovalError("verdict must be 'approve' or 'reject'")
        if datetime.now(UTC) >= challenge.expires_at:
            raise ApprovalError("challenge expired")
        # Separation of duties: the requester cannot approve their own call.
        if approver == challenge.requested_by:
            raise ApprovalError("requester cannot approve their own call")
        expected = sign_approval(self._key, challenge, approver, verdict)
        if not hmac.compare_digest(expected, signature):
            raise ApprovalError("signature mismatch")
        if verdict == APPROVE:
            self._approved.add((challenge.requested_by, challenge.call_digest))
        return verdict == APPROVE

    def consume_approval(
        self, requested_by: str, tool_name: str, arguments: dict[str, Any]
    ) -> bool:
        """True exactly once if this exact call was approved for this user."""
        key = (requested_by, call_digest(tool_name, arguments))
        if key not in self._approved:
            return False
        self._approved.discard(key)
        return True
