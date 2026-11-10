"""Mint a short-lived identity token for local testing.

In production the identity provider issues these tokens. This script exists so
the HTTP API can be tried on a laptop; it signs with AEGIS_IDENTITY_SECRET, so
anyone who can run it already holds the key.

Usage: python lab/mint_dev_token.py <subject> <tenant> [role ...]
"""

from __future__ import annotations

import os
import sys
from datetime import UTC, datetime, timedelta

import jwt

TOKEN_LIFETIME = timedelta(minutes=15)
SECRET_ENV = "AEGIS_IDENTITY_SECRET"  # noqa: S105 - the variable's name, not a secret
MIN_ARGUMENTS = 2
EXIT_USAGE = 2


def mint(subject: str, tenant_id: str, roles: list[str], secret: str) -> str:
    """Return an HS256 token carrying the claims aegis-mcp requires."""
    now = datetime.now(UTC)
    claims = {
        "sub": subject,
        "tenant_id": tenant_id,
        "roles": roles,
        "iss": os.environ.get("AEGIS_ISSUER", "https://idp.example.com"),
        "aud": os.environ.get("AEGIS_AUDIENCE", "aegis-mcp"),
        "iat": now,
        "exp": now + TOKEN_LIFETIME,
    }
    return jwt.encode(claims, secret, algorithm="HS256")


def main(argv: list[str]) -> int:
    secret = os.environ.get(SECRET_ENV, "")
    if len(argv) < MIN_ARGUMENTS or not secret:
        sys.stderr.write(
            f"usage: {SECRET_ENV}=... mint_dev_token.py <subject> <tenant> [role ...]\n"
        )
        return EXIT_USAGE
    subject, tenant_id, *roles = argv
    sys.stdout.write(mint(subject, tenant_id, roles, secret) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
