"""Shared fixtures. All keys are random per test; nothing here is a real secret."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from aegis.agency_guard import UserIdentity
from aegis.api.app import create_app
from aegis.redteam.lab import build_lab_services, mint_token
from aegis.runtime import Services


@pytest.fixture
def services() -> Services:
    return build_lab_services()


@pytest.fixture
def client(services: Services) -> TestClient:
    return TestClient(create_app(services, lab_enabled=True))


@pytest.fixture
def auth(services: Services) -> Any:
    """Factory for Authorization headers carrying a lab identity token."""

    def _headers(roles: list[str], subject: str = "alice", tenant: str = "tenant-acme") -> Any:
        token = mint_token(services, subject, roles, tenant_id=tenant)
        return {"Authorization": f"Bearer {token}"}

    return _headers


@pytest.fixture
def weather_tool() -> dict[str, Any]:
    return {
        "name": "get_weather",
        "description": "Returns the weather for a city.",
        "inputSchema": {
            "type": "object",
            "properties": {"city": {"type": "string", "maxLength": 80}},
            "required": ["city"],
        },
    }


def identity(
    subject: str = "alice", tenant: str = "tenant-acme", roles: tuple[str, ...] = ()
) -> UserIdentity:
    return UserIdentity(subject=subject, tenant_id=tenant, roles=frozenset(roles))
