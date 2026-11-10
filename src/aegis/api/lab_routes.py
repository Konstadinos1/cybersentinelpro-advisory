"""Attack lab: run red-team cases from the browser.

Safe to expose because a visitor chooses only *which* shipped case runs.
No request field reaches a guard, and every case gets a throwaway
environment with random keys.
"""

from __future__ import annotations

import math
from functools import lru_cache
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel

from aegis.api.rate_limit import SlidingWindowLimiter
from aegis.api.site_routes import html_page
from aegis.redteam import AttackCase, CaseResult, load_corpus, run_case
from aegis.redteam.lab import render

router = APIRouter(prefix="/lab", tags=["lab"])

UNKNOWN_CLIENT = "unknown"


class CaseSummary(BaseModel):
    id: str
    title: str
    module: str
    kind: str
    expect: str
    description: str
    references: tuple[str, ...]
    input: dict[str, Any]


@lru_cache(maxsize=1)
def _corpus() -> dict[str, AttackCase]:
    """The shipped corpus, parsed once per process."""
    return {case.id: case for case in load_corpus()}


def client_key(request: Request) -> str:
    """Identify the caller for rate limiting.

    A forwarding header is trusted only when the deployment names one, since
    anywhere else the client could set it to dodge the limit.
    """
    header_name: str | None = request.app.state.client_ip_header
    if header_name:
        forwarded = request.headers.get(header_name, "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else UNKNOWN_CLIENT


def enforce_run_limit(request: Request) -> None:
    limiter: SlidingWindowLimiter | None = request.app.state.run_limiter
    if limiter is None or limiter.allow(client_key(request)):
        return
    raise HTTPException(
        status.HTTP_429_TOO_MANY_REQUESTS,
        "rate limit reached; try again shortly",
        headers={"Retry-After": str(math.ceil(limiter.window_seconds))},
    )


RunLimit = Annotated[None, Depends(enforce_run_limit)]


@router.get("", include_in_schema=False)
def lab_page() -> Response:
    return html_page("lab.html")


@router.get("/api/cases")
def list_cases() -> list[CaseSummary]:
    """The corpus, with placeholders rendered so payloads are visible."""
    return [
        CaseSummary(**case.model_dump(exclude={"input"}), input=render(case.input))
        for case in _corpus().values()
    ]


@router.post("/api/cases/{case_id}/run")
def run_one(case_id: str, _: RunLimit) -> CaseResult:
    case = _corpus().get(case_id)
    if case is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown case")
    return run_case(case)
