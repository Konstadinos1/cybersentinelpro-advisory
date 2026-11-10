"""Vercel entry point for the public demo site.

Vercel looks for a FastAPI instance named ``app`` in ``main.py``. This serves
the landing page and the read-only attack lab only: the guard API and the
interactive docs are not mounted in public demo mode.
"""

from __future__ import annotations

import sys
from pathlib import Path

# The package lives under src/. Adding it keeps this working whether or not
# the platform installs the project itself before importing this file.
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from aegis.api.app import create_app
from aegis.api.modes import AppMode
from aegis.redteam.lab import build_lab_services

# Vercel overwrites this header with the real client address, so a visitor
# cannot forge it to dodge the rate limit. Do not copy this to other hosts.
VERCEL_CLIENT_IP_HEADER = "x-forwarded-for"

app = create_app(
    build_lab_services(),
    mode=AppMode.PUBLIC_DEMO,
    client_ip_header=VERCEL_CLIENT_IP_HEADER,
)
