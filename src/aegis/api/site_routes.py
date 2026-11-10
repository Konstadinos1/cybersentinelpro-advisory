"""Landing page and static assets for the demo modes."""

from __future__ import annotations

from importlib import resources

from fastapi import APIRouter, HTTPException, Response, status

router = APIRouter(include_in_schema=False)

HTML = "text/html; charset=utf-8"
STATIC_FILES = {
    "base.css": "text/css; charset=utf-8",
    "landing.css": "text/css; charset=utf-8",
    "landing.js": "text/javascript; charset=utf-8",
    "lab.css": "text/css; charset=utf-8",
    "lab.js": "text/javascript; charset=utf-8",
}
# Assets are tiny and change only on deploy; a short cache keeps the pages
# quick without making a new release wait long to show up.
STATIC_CACHE_CONTROL = "public, max-age=300"


def read_static(name: str) -> str:
    return resources.files("aegis.api").joinpath("static", name).read_text("utf-8")


def html_page(name: str) -> Response:
    return Response(read_static(name), media_type=HTML)


@router.get("/")
def landing_page() -> Response:
    return html_page("landing.html")


@router.get("/static/{name}")
def static_file(name: str) -> Response:
    # Lookup in a fixed table, never a filesystem path built from user input.
    media_type = STATIC_FILES.get(name)
    if media_type is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    return Response(
        read_static(name), media_type=media_type, headers={"Cache-Control": STATIC_CACHE_CONTROL}
    )
