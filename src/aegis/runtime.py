"""Configuration loading and wiring of all guard modules.

Secrets come from the environment only. In lab mode missing secrets are
generated per process so the demo runs with zero setup; outside lab mode a
missing or short secret is a startup error.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from aegis.agency_guard import (
    AgencyGuard,
    ApprovalGate,
    CircuitBreaker,
    IdentityVerifier,
    Policy,
    PolicyEngine,
    RunBudget,
)
from aegis.io_sanitization import DlpRedactor, PackageAllowlist, ShellPolicy, SqlPolicy
from aegis.mcp_firewall import McpFirewall, ToolManifest
from aegis.rag_guard import HashingEmbedder, RagGuard, TenantVectorStore

SECRET_MIN_CHARS = 32
GENERATED_SECRET_BYTES = 48
ENV_PREFIX = "AEGIS_"


class ConfigError(Exception):
    """Configuration is missing or unsafe; the service must not start."""


class SinkConfig(BaseModel):
    shell: ShellPolicy = ShellPolicy()
    sql: SqlPolicy = SqlPolicy()
    image_hosts: frozenset[str] = frozenset()
    packages: dict[str, frozenset[str]] = Field(default_factory=dict)


class RagConfig(BaseModel):
    trusted_source_hosts: frozenset[str] = frozenset()


class AegisConfig(BaseModel):
    """Non-secret configuration, loaded from YAML."""

    policy: Policy = Policy()
    budget: RunBudget = RunBudget()
    sinks: SinkConfig = SinkConfig()
    rag: RagConfig = RagConfig()


class Secrets(BaseModel):
    """Key material. ``repr`` is suppressed so it never lands in a log."""

    model_config = ConfigDict(frozen=True)

    identity_secret: str = Field(repr=False)
    approval_key: str = Field(repr=False)
    issuer: str = "https://idp.example.com"
    audience: str = "aegis-mcp"
    canaries: tuple[str, ...] = Field(default=(), repr=False)


@dataclass
class Services:
    """Everything the API and the red-team runner need, already wired."""

    config: AegisConfig
    secrets: Secrets
    firewall: McpFirewall
    verifier: IdentityVerifier
    policy: PolicyEngine
    guard: AgencyGuard
    dlp: DlpRedactor
    packages: PackageAllowlist
    rag_store: TenantVectorStore
    rag: RagGuard


def load_config(path: Path | None = None) -> AegisConfig:
    """Load YAML config, falling back to the packaged default."""
    if path is None:
        text = resources.files("aegis").joinpath("default_config.yaml").read_text("utf-8")
    else:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as error:
            raise ConfigError(f"cannot read config {path}: {error}") from error
    document: Any = yaml.safe_load(text) or {}
    return AegisConfig.model_validate(document)


def _secret_from_env(name: str, lab_mode: bool) -> str:
    value = os.environ.get(ENV_PREFIX + name, "")
    if len(value) >= SECRET_MIN_CHARS:
        return value
    if lab_mode:
        return secrets.token_urlsafe(GENERATED_SECRET_BYTES)
    raise ConfigError(f"{ENV_PREFIX}{name} must be set to at least {SECRET_MIN_CHARS} characters")


def load_secrets(lab_mode: bool) -> Secrets:
    """Read key material from the environment."""
    canaries = tuple(c for c in os.environ.get(ENV_PREFIX + "CANARIES", "").split(",") if c)
    return Secrets(
        identity_secret=_secret_from_env("IDENTITY_SECRET", lab_mode),
        approval_key=_secret_from_env("APPROVAL_KEY", lab_mode),
        issuer=os.environ.get(ENV_PREFIX + "ISSUER", "https://idp.example.com"),
        audience=os.environ.get(ENV_PREFIX + "AUDIENCE", "aegis-mcp"),
        canaries=canaries,
    )


def build_services(
    config: AegisConfig, secrets_: Secrets, manifest: ToolManifest | None = None
) -> Services:
    """Wire every module from configuration."""
    verifier = IdentityVerifier(
        secrets_.identity_secret, issuer=secrets_.issuer, audience=secrets_.audience
    )
    policy = PolicyEngine(config.policy)
    guard = AgencyGuard(
        verifier,
        policy,
        CircuitBreaker(config.budget),
        ApprovalGate(secrets_.approval_key.encode("utf-8")),
    )
    store = TenantVectorStore(HashingEmbedder())
    return Services(
        config=config,
        secrets=secrets_,
        firewall=McpFirewall(manifest or ToolManifest()),
        verifier=verifier,
        policy=policy,
        guard=guard,
        dlp=DlpRedactor(canaries=secrets_.canaries),
        packages=PackageAllowlist(config.sinks.packages),
        rag_store=store,
        rag=RagGuard(store, config.rag.trusted_source_hosts),
    )


def services_from_environment() -> Services:
    """Entry point used by the API process."""
    lab_mode = os.environ.get(ENV_PREFIX + "LAB_MODE", "") == "1"
    config_path = os.environ.get(ENV_PREFIX + "CONFIG_PATH")
    config = load_config(Path(config_path) if config_path else None)
    return build_services(config, load_secrets(lab_mode))
