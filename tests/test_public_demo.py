"""The internet-facing demo: what it exposes, what it must not, and its rate limit."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from aegis.api import app as app_module
from aegis.api.app import app_from_environment, create_app
from aegis.api.modes import AppMode, mode_from_environment
from aegis.api.rate_limit import SlidingWindowLimiter
from aegis.cli import EXIT_OK, main
from aegis.runtime import Services

ROOT = Path(__file__).resolve().parent.parent
RUN_URL = "/lab/api/cases/RT-MCP-001/run"


@pytest.fixture
def demo(services: Services) -> TestClient:
    return TestClient(create_app(services, mode=AppMode.PUBLIC_DEMO))


# ------------------------------------------------------------------ surface


def test_public_demo_serves_landing_lab_and_assets(demo: TestClient) -> None:
    landing = demo.get("/")
    assert landing.status_code == 200
    assert "Open the attack lab" in landing.text
    assert demo.get("/lab").status_code == 200
    assert len(demo.get("/lab/api/cases").json()) >= 70
    for asset in ("base.css", "landing.css", "landing.js", "lab.css", "lab.js"):
        response = demo.get(f"/static/{asset}")
        assert response.status_code == 200, asset
        assert "max-age" in response.headers["Cache-Control"]
    assert demo.get("/static/not-a-file.css").status_code == 404
    assert demo.get("/static/landing.html").status_code == 404


def test_public_demo_runs_a_real_case(demo: TestClient) -> None:
    result = demo.post(RUN_URL).json()
    assert result["passed"] is True
    assert result["outcome"]["blocked"] is True
    assert "AEGIS-TP-010" in result["outcome"]["rule_ids"]


@pytest.mark.parametrize(
    "path",
    [
        "/v1/mcp/tools/inspect",
        "/v1/mcp/tools/approve",
        "/v1/mcp/call/authorize",
        "/v1/approvals/anything",
        "/v1/output/sanitize",
        "/v1/sinks/shell",
        "/v1/sinks/sql",
        "/v1/rag/ingest",
        "/v1/rag/query",
    ],
)
def test_public_demo_does_not_mount_the_guard_api(demo: TestClient, path: str) -> None:
    assert demo.post(path, json={}).status_code == 404


@pytest.mark.parametrize("path", ["/docs", "/openapi.json", "/redoc"])
def test_public_demo_has_no_api_docs(demo: TestClient, path: str) -> None:
    assert demo.get(path).status_code == 404


def test_run_endpoint_ignores_any_request_body(demo: TestClient) -> None:
    """A visitor picks a case; nothing they send reaches a guard."""
    payload = {"input": {"advertised": {"name": "x", "description": "harmless"}}}
    result = demo.post(RUN_URL, json=payload).json()
    assert result["outcome"]["blocked"] is True
    assert demo.post("/lab/api/cases/..%2F..%2Fetc/run").status_code == 404
    assert demo.post("/lab/api/cases/NOT-A-CASE/run").status_code == 404


def test_pages_have_no_inline_script_or_style_and_a_strict_csp(demo: TestClient) -> None:
    for path in ("/", "/lab"):
        page = demo.get(path)
        assert "<style" not in page.text
        assert " style=" not in page.text
        assert "onclick" not in page.text
        assert "<script src=" in page.text
        csp = page.headers["Content-Security-Policy"]
        assert "default-src 'none'" in csp
        assert "'unsafe-inline'" not in csp
    for script in ("landing.js", "lab.js"):
        assert "innerHTML =" not in demo.get(f"/static/{script}").text


def test_every_same_site_link_on_the_landing_page_resolves(demo: TestClient) -> None:
    import re  # noqa: PLC0415

    page = demo.get("/").text
    local = set(re.findall(r'(?:href|src)="(/[^"]*)"', page))
    assert {"/lab", "/static/base.css", "/static/landing.js"} <= local
    for link in local:
        assert demo.get(link).status_code == 200, link


# --------------------------------------------------------------- rate limit


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_limiter_allows_up_to_the_limit_then_refuses() -> None:
    limiter = SlidingWindowLimiter(3, 60, clock=FakeClock())
    assert [limiter.allow("a") for _ in range(4)] == [True, True, True, False]
    assert limiter.allow("b") is True


def test_limiter_window_slides() -> None:
    clock = FakeClock()
    limiter = SlidingWindowLimiter(2, 60, clock=clock)
    assert limiter.allow("a") and limiter.allow("a")
    clock.now = 59.9
    assert limiter.allow("a") is False
    clock.now = 60.0
    assert limiter.allow("a") is True


def test_limiter_forgets_idle_keys_and_stays_bounded() -> None:
    clock = FakeClock()
    limiter = SlidingWindowLimiter(1, 60, max_tracked_keys=3, clock=clock)
    for key in ("a", "b", "c"):
        assert limiter.allow(key)
    clock.now = 61.0
    assert limiter.allow("d")
    assert len(limiter._hits) == 1


def test_limiter_evicts_oldest_when_every_key_is_still_active() -> None:
    limiter = SlidingWindowLimiter(1, 60, max_tracked_keys=2, clock=FakeClock())
    assert limiter.allow("a") and limiter.allow("b") and limiter.allow("c")
    assert set(limiter._hits) == {"b", "c"}


@pytest.mark.parametrize("arguments", [(0, 60), (1, 0), (-1, 60)])
def test_limiter_rejects_non_positive_limits(arguments: tuple[int, int]) -> None:
    with pytest.raises(ValueError, match="positive"):
        SlidingWindowLimiter(*arguments)
    with pytest.raises(ValueError, match="positive"):
        SlidingWindowLimiter(1, 1, max_tracked_keys=0)


def _limited_client(
    services: Services, monkeypatch: pytest.MonkeyPatch, **kwargs: Any
) -> TestClient:
    monkeypatch.setattr(app_module, "PUBLIC_DEMO_RUNS_PER_WINDOW", 2)
    return TestClient(create_app(services, mode=AppMode.PUBLIC_DEMO, **kwargs))


def test_run_endpoint_returns_429_with_retry_after(
    services: Services, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _limited_client(services, monkeypatch)
    assert [client.post(RUN_URL).status_code for _ in range(3)] == [200, 200, 429]
    refused = client.post(RUN_URL)
    assert refused.headers["Retry-After"] == "60"
    assert client.get("/lab/api/cases").status_code == 200
    assert client.get("/").status_code == 200


def test_limit_is_per_client_when_a_trusted_proxy_header_is_configured(
    services: Services, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _limited_client(services, monkeypatch, client_ip_header="x-forwarded-for")
    alice = {"x-forwarded-for": "203.0.113.7, 10.0.0.1"}
    bob = {"x-forwarded-for": "203.0.113.8"}
    assert [client.post(RUN_URL, headers=alice).status_code for _ in range(3)] == [200, 200, 429]
    assert client.post(RUN_URL, headers=bob).status_code == 200
    assert client.post(RUN_URL).status_code == 200


def test_forwarding_header_cannot_dodge_the_limit_unless_configured(
    services: Services, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _limited_client(services, monkeypatch)
    codes = [
        client.post(RUN_URL, headers={"x-forwarded-for": f"198.51.100.{n}"}).status_code
        for n in range(3)
    ]
    assert codes == [200, 200, 429]


def test_lab_mode_is_not_rate_limited(client: TestClient) -> None:
    assert client.app.state.run_limiter is None  # type: ignore[attr-defined]


# -------------------------------------------------------------------- modes


@pytest.mark.parametrize(
    ("environment", "expected"),
    [
        ({}, AppMode.PRODUCTION),
        ({"AEGIS_LAB_MODE": "1"}, AppMode.LAB),
        ({"AEGIS_PUBLIC_DEMO": "1"}, AppMode.PUBLIC_DEMO),
        ({"AEGIS_LAB_MODE": "1", "AEGIS_PUBLIC_DEMO": "1"}, AppMode.PUBLIC_DEMO),
        ({"AEGIS_PUBLIC_DEMO": "true"}, AppMode.PRODUCTION),
    ],
)
def test_mode_from_environment(
    monkeypatch: pytest.MonkeyPatch, environment: dict[str, str], expected: AppMode
) -> None:
    for name in ("AEGIS_LAB_MODE", "AEGIS_PUBLIC_DEMO"):
        monkeypatch.delenv(name, raising=False)
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    assert mode_from_environment() is expected


def test_public_demo_starts_from_environment_without_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in ("AEGIS_LAB_MODE", "AEGIS_IDENTITY_SECRET", "AEGIS_APPROVAL_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AEGIS_PUBLIC_DEMO", "1")
    monkeypatch.setenv("AEGIS_CLIENT_IP_HEADER", "x-real-ip")
    app = app_from_environment()
    assert app.state.client_ip_header == "x-real-ip"
    assert app.state.run_limiter is not None
    client = TestClient(app)
    assert client.get("/").status_code == 200
    assert client.post("/v1/sinks/shell", json={"command": "ls"}).status_code == 404


def test_cli_serve_public_demo_flag_sets_the_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    import uvicorn  # noqa: PLC0415

    monkeypatch.setattr(uvicorn, "run", lambda *args, **kwargs: None)
    for name in ("AEGIS_LAB_MODE", "AEGIS_PUBLIC_DEMO"):
        monkeypatch.delenv(name, raising=False)
    assert main(["serve", "--public-demo"]) == EXIT_OK
    assert mode_from_environment() is AppMode.PUBLIC_DEMO
    monkeypatch.delenv("AEGIS_PUBLIC_DEMO", raising=False)


# --------------------------------------------------------- vercel entry point


def test_vercel_entrypoint_exposes_only_the_public_demo() -> None:
    spec = importlib.util.spec_from_file_location("vercel_main", ROOT / "main.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    client = TestClient(module.app)
    assert client.get("/").status_code == 200
    assert client.get("/healthz").json()["status"] == "ok"
    assert client.post(RUN_URL).json()["passed"] is True
    assert client.post("/v1/sinks/shell", json={"command": "ls"}).status_code == 404
    assert client.get("/docs").status_code == 404
    assert module.app.state.client_ip_header == "x-forwarded-for"
