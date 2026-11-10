"""Attack lab: run red-team cases from the browser. Lab mode only."""

from __future__ import annotations

from importlib import resources
from typing import Any

from fastapi import APIRouter, HTTPException, Response, status
from pydantic import BaseModel

from aegis.redteam import CaseResult, load_corpus, run_case
from aegis.redteam.lab import render

router = APIRouter(prefix="/lab", tags=["lab"])

STATIC_FILES = {
    "lab.css": "text/css; charset=utf-8",
    "lab.js": "text/javascript; charset=utf-8",
}


class CaseSummary(BaseModel):
    id: str
    title: str
    module: str
    kind: str
    expect: str
    description: str
    references: tuple[str, ...]
    input: dict[str, Any]


def _static(name: str) -> str:
    return resources.files("aegis.api").joinpath("static", name).read_text("utf-8")


@router.get("", include_in_schema=False)
def lab_page() -> Response:
    return Response(_static("lab.html"), media_type="text/html; charset=utf-8")


@router.get("/static/{name}", include_in_schema=False)
def lab_static(name: str) -> Response:
    # Lookup in a fixed table, never a filesystem path built from user input.
    media_type = STATIC_FILES.get(name)
    if media_type is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    return Response(_static(name), media_type=media_type)


@router.get("/api/cases")
def list_cases() -> list[CaseSummary]:
    """The corpus, with placeholders rendered so payloads are visible."""
    return [
        CaseSummary(**case.model_dump(exclude={"input"}), input=render(case.input))
        for case in load_corpus()
    ]


@router.post("/api/cases/{case_id}/run")
def run_one(case_id: str) -> CaseResult:
    for case in load_corpus():
        if case.id == case_id:
            return run_case(case)
    raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown case")
