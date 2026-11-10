"""FastAPI application factory."""

from __future__ import annotations

import logging
import os
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response

from aegis import __version__
from aegis.api import lab_routes, routes, site_routes
from aegis.api.modes import AppMode, mode_from_environment
from aegis.api.rate_limit import SlidingWindowLimiter
from aegis.runtime import ENV_PREFIX, Services, services_from_environment

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    # No inline script or style anywhere, so attack payloads shown in the lab
    # cannot execute even if a rendering bug were introduced.
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; "
    "connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; "
    "form-action 'none'",
}

# Running the whole corpus once is 79 requests; this allows three full runs a
# minute per client and nothing like a sustained load.
PUBLIC_DEMO_RUNS_PER_WINDOW = 240
PUBLIC_DEMO_WINDOW_SECONDS = 60.0

_logger = logging.getLogger("aegis.api")


def _mount_routes(app: FastAPI, mode: AppMode) -> None:
    """Mount only what the mode is meant to expose."""
    if mode is not AppMode.PUBLIC_DEMO:
        app.include_router(routes.router)
    if mode is not AppMode.PRODUCTION:
        app.include_router(site_routes.router)
        app.include_router(lab_routes.router)
    if mode is AppMode.LAB:
        _logger.warning("lab mode is enabled; do not expose this instance to untrusted networks")


def _attach_state(
    app: FastAPI, services: Services, mode: AppMode, client_ip_header: str | None
) -> None:
    """Hang the shared objects the route dependencies read off the app."""
    app.state.services = services
    app.state.client_ip_header = client_ip_header
    app.state.run_limiter = (
        SlidingWindowLimiter(PUBLIC_DEMO_RUNS_PER_WINDOW, PUBLIC_DEMO_WINDOW_SECONDS)
        if mode is AppMode.PUBLIC_DEMO
        else None
    )


def create_app(
    services: Services,
    *,
    mode: AppMode = AppMode.PRODUCTION,
    client_ip_header: str | None = None,
) -> FastAPI:
    """Build the app around already-wired services (easy to test).

    ``client_ip_header`` names the header a trusted proxy sets to the real
    client address. Leave it unset unless such a proxy is in front.
    """
    lab = mode is AppMode.LAB
    app = FastAPI(
        title="aegis-mcp",
        version=__version__,
        description="Zero-trust guard engine for MCP and agentic AI applications.",
        # Interactive docs pull scripts from a CDN and describe every route,
        # so they and the schema exist only in local lab mode.
        docs_url="/docs" if lab else None,
        openapi_url="/openapi.json" if lab else None,
        redoc_url=None,
    )
    _attach_state(app, services, mode, client_ip_header)
    _mount_routes(app, mode)

    @app.middleware("http")
    async def add_security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        # Swagger UI needs CDN scripts the policy forbids; it exists only in lab mode.
        if not (lab and request.url.path.startswith("/docs")):
            for header, value in SECURITY_HEADERS.items():
                response.headers.setdefault(header, value)
        return response

    @app.get("/healthz", tags=["meta"])
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    return app


def app_from_environment() -> FastAPI:
    """Uvicorn factory: ``uvicorn aegis.api.app:app_from_environment --factory``."""
    return create_app(
        services_from_environment(),
        mode=mode_from_environment(),
        client_ip_header=os.environ.get(ENV_PREFIX + "CLIENT_IP_HEADER") or None,
    )
