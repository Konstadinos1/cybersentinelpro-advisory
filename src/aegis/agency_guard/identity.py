"""Verification of the human user's identity token.

Authorisation decisions are bound to the *human* on whose behalf the agent
acts. The agent's own service credentials are never consulted, which is
what stops a confused-deputy attack: an agent with broad delegated access
cannot be talked into using it for a user who lacks that access.
"""

from __future__ import annotations

import jwt
from pydantic import BaseModel, ConfigDict, Field, ValidationError

# Pinned so a token cannot downgrade itself to "none" or switch key type.
ALLOWED_ALGORITHMS = ("HS256",)
REQUIRED_CLAIMS = ("exp", "iat", "sub", "aud", "iss")
SECRET_MIN_BYTES = 32
CLOCK_SKEW_SECONDS = 30


class IdentityError(Exception):
    """The token is missing, malformed, expired, or not meant for this service."""


class UserIdentity(BaseModel):
    """The verified human principal."""

    model_config = ConfigDict(frozen=True)

    subject: str = Field(min_length=1)
    tenant_id: str = Field(min_length=1)
    roles: frozenset[str] = Field(default_factory=frozenset)


class IdentityVerifier:
    """Validates HS256 JWTs issued by the organisation's identity provider."""

    def __init__(self, secret: str, *, issuer: str, audience: str) -> None:
        if len(secret.encode("utf-8")) < SECRET_MIN_BYTES:
            raise ValueError(f"identity secret must be at least {SECRET_MIN_BYTES} bytes")
        self._secret = secret
        self._issuer = issuer
        self._audience = audience

    def verify(self, token: str) -> UserIdentity:
        """Return the identity carried by ``token`` or raise ``IdentityError``."""
        try:
            claims = jwt.decode(
                token,
                self._secret,
                algorithms=list(ALLOWED_ALGORITHMS),
                audience=self._audience,
                issuer=self._issuer,
                leeway=CLOCK_SKEW_SECONDS,
                options={"require": list(REQUIRED_CLAIMS)},
            )
            return UserIdentity(
                subject=claims["sub"],
                tenant_id=claims.get("tenant_id", ""),
                roles=frozenset(claims.get("roles", [])),
            )
        except (jwt.PyJWTError, ValidationError, TypeError) as error:
            # The reason is kept generic for callers; details stay in the chain.
            raise IdentityError("identity token rejected") from error
