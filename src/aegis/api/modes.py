"""Which surfaces an instance exposes.

The three modes differ in what an anonymous caller can reach, so the choice
is explicit and made once at start-up rather than spread over feature flags.
"""

from __future__ import annotations

import os
from enum import StrEnum

from aegis.runtime import ENV_PREFIX


class AppMode(StrEnum):
    # The guard API only. Every route needs a verified identity token.
    PRODUCTION = "production"
    # Local demo: guard API, attack lab, landing page and interactive docs.
    LAB = "lab"
    # Internet-facing demo: landing page and read-only attack lab. The guard
    # API and the docs are not mounted at all, and case runs are rate limited.
    PUBLIC_DEMO = "public_demo"


def mode_from_environment() -> AppMode:
    """Resolve the mode from AEGIS_* variables; the narrower demo mode wins."""
    if os.environ.get(ENV_PREFIX + "PUBLIC_DEMO", "") == "1":
        return AppMode.PUBLIC_DEMO
    if os.environ.get(ENV_PREFIX + "LAB_MODE", "") == "1":
        return AppMode.LAB
    return AppMode.PRODUCTION
