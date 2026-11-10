from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

from aegis.agency_guard import IdentityVerifier

SCRIPT = Path(__file__).resolve().parent.parent / "lab" / "mint_dev_token.py"
SECRET = "d" * 48


def _load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("mint_dev_token", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_minted_token_is_accepted_by_the_verifier(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("AEGIS_IDENTITY_SECRET", SECRET)
    monkeypatch.delenv("AEGIS_ISSUER", raising=False)
    monkeypatch.delenv("AEGIS_AUDIENCE", raising=False)
    assert _load_script().main(["alice", "tenant-acme", "operator", "rag-writer"]) == 0
    token = capsys.readouterr().out.strip()
    verifier = IdentityVerifier(SECRET, issuer="https://idp.example.com", audience="aegis-mcp")
    user = verifier.verify(token)
    assert (user.subject, user.tenant_id) == ("alice", "tenant-acme")
    assert user.roles == frozenset({"operator", "rag-writer"})


def test_token_without_roles_is_valid_but_carries_none(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("AEGIS_IDENTITY_SECRET", SECRET)
    assert _load_script().main(["bob", "tenant-acme"]) == 0
    verifier = IdentityVerifier(SECRET, issuer="https://idp.example.com", audience="aegis-mcp")
    assert verifier.verify(capsys.readouterr().out.strip()).roles == frozenset()


@pytest.mark.parametrize("argv", [[], ["only-subject"]])
def test_missing_arguments_print_usage(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], argv: list[str]
) -> None:
    monkeypatch.setenv("AEGIS_IDENTITY_SECRET", SECRET)
    assert _load_script().main(argv) == 2
    assert "usage:" in capsys.readouterr().err


def test_missing_secret_prints_usage(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("AEGIS_IDENTITY_SECRET", raising=False)
    assert _load_script().main(["alice", "tenant-acme"]) == 2
    assert "usage:" in capsys.readouterr().err
