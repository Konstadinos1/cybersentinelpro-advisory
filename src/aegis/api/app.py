"""FastAPI application factory."""

from __future__ import annotations

import logging
import os
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response

from aegis import __version__
from aegis.api import lab_routes, routes
from aegis.runtime import ENV_PREFIX, Services, services_from_environment

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    # No inline script or style anywhere, so attack payloads shown in the lab
    # cannot execute even if a rendering bug were introduced.
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; "
    "connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'",
}

_logger = logging.getLogger("aegis.api")


def create_app(services: Services, *, lab_enabled: bool = False) -> FastAPI:
    """Build the app around already-wired services (easy to test)."""
    app = FastAPI(
        title="aegis-mcp",
        version=__version__,
        description="Zero-trust guard engine for MCP and agentic AI applications.",
        # Interactive docs pull scripts from a CDN; only offered in lab mode.
        docs_url="/docs" if lab_enabled else None,
        redoc_url=None,
    )
    app.state.services = services
    app.include_router(routes.router)
    if lab_enabled:
        app.include_router(lab_routes.router)
        _logger.warning("lab mode is enabled; do not expose this instance to untrusted networks")

    @app.middleware("http")
    async def add_security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        if not request.url.path.startswith("/docs"):
            for header, value in SECURITY_HEADERS.items():
                response.headers.setdefault(header, value)
        return response

    @app.get("/healthz", tags=["meta"])
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    return app


def app_from_environment() -> FastAPI:
    """Uvicorn factory: ``uvicorn aegis.api.app:app_from_environment --factory``."""
    lab_enabled = os.environ.get(ENV_PREFIX + "LAB_MODE", "") == "1"
    return create_app(services_from_environment(), lab_enabled=lab_enabled)
