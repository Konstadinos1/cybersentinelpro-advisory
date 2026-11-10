"""Cryptographic pinning of approved MCP tool schemas.

A "rug pull" is a server that advertises a benign tool, gets approved, and
later changes the description or schema. Pinning the SHA-256 of everything
the model is shown turns that mutation into a hard failure until a human
re-approves.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, Field, ValidationError

from aegis.core.canonical import canonical_json, sha256_hex
from aegis.mcp_firewall.models import McpTool

MANIFEST_VERSION = 1
HASH_ALGORITHM = "sha256"
SIGNING_KEY_MIN_BYTES = 32


class ManifestError(Exception):
    """The lock file is missing, malformed, or fails its integrity check."""


class PinStatus(StrEnum):
    MATCH = "match"
    MUTATED = "mutated"
    UNPINNED = "unpinned"


class PinnedTool(BaseModel):
    sha256: str
    approved_by: str
    approved_at: datetime


class ServerPins(BaseModel):
    tools: dict[str, PinnedTool] = Field(default_factory=dict)


class ToolManifest(BaseModel):
    """Lock file content: server id -> tool name -> pinned digest."""

    version: int = MANIFEST_VERSION
    algorithm: str = HASH_ALGORITHM
    servers: dict[str, ServerPins] = Field(default_factory=dict)

    def pin(self, server_id: str, tool: McpTool, approved_by: str) -> PinnedTool:
        """Record a human approval of the tool exactly as currently advertised."""
        pinned = PinnedTool(
            sha256=tool_digest(tool), approved_by=approved_by, approved_at=datetime.now(UTC)
        )
        self.servers.setdefault(server_id, ServerPins()).tools[tool.name] = pinned
        return pinned

    def verify(self, server_id: str, tool: McpTool) -> PinStatus:
        """Compare the advertised tool with its pin."""
        pinned = self.pinned_tool(server_id, tool.name)
        if pinned is None:
            return PinStatus.UNPINNED
        if hmac.compare_digest(pinned.sha256, tool_digest(tool)):
            return PinStatus.MATCH
        return PinStatus.MUTATED

    def pinned_tool(self, server_id: str, tool_name: str) -> PinnedTool | None:
        server = self.servers.get(server_id)
        return server.tools.get(tool_name) if server else None

    def removed_tools(self, server_id: str, advertised_names: set[str]) -> list[str]:
        """Pinned tools the server no longer advertises (worth alerting on)."""
        server = self.servers.get(server_id)
        if server is None:
            return []
        return sorted(set(server.tools) - advertised_names)


def tool_digest(tool: McpTool) -> str:
    """SHA-256 over the canonical form of everything the model is shown."""
    return sha256_hex(tool.pinned_view())


def _signature(manifest: ToolManifest, signing_key: bytes) -> str:
    payload = canonical_json(manifest.model_dump(mode="json"))
    return hmac.new(signing_key, payload, hashlib.sha256).hexdigest()


def _require_strong_key(signing_key: bytes) -> None:
    if len(signing_key) < SIGNING_KEY_MIN_BYTES:
        raise ManifestError(f"signing key must be at least {SIGNING_KEY_MIN_BYTES} bytes")


def save_manifest(manifest: ToolManifest, path: Path, signing_key: bytes) -> None:
    """Write the lock file with an HMAC so tampering on disk is detectable."""
    _require_strong_key(signing_key)
    document = {
        "manifest": manifest.model_dump(mode="json"),
        "hmac_sha256": _signature(manifest, signing_key),
    }
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_manifest(path: Path, signing_key: bytes) -> ToolManifest:
    """Read and authenticate the lock file; fail closed on any problem."""
    _require_strong_key(signing_key)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        manifest = ToolManifest.model_validate(document["manifest"])
        recorded = str(document["hmac_sha256"])
    except (OSError, ValueError, KeyError, TypeError, ValidationError) as error:
        raise ManifestError(f"cannot read manifest {path}: {error}") from error
    if not hmac.compare_digest(recorded, _signature(manifest, signing_key)):
        raise ManifestError(f"manifest {path} failed its integrity check")
    return manifest
