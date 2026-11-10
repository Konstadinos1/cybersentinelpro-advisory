"""Tenant-isolated vector store.

Isolation is structural, not a filter the caller remembers to add: chunks
live in per-tenant partitions and the only way to reach a partition is
through a verified ``UserIdentity``. There is no API that accepts a tenant
id as a query parameter.
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from aegis.agency_guard.identity import UserIdentity
from aegis.core.canonical import sha256_hex
from aegis.rag_guard.embedding import Embedder, cosine_similarity

DEFAULT_TOP_K = 4
MAX_TOP_K = 20


class Chunk(BaseModel):
    """One retrievable unit with provenance and an integrity digest."""

    model_config = ConfigDict(frozen=True)

    chunk_id: str
    tenant_id: str
    text: str
    source: str
    allowed_roles: frozenset[str] = Field(default_factory=frozenset)
    ingested_by: str
    ingested_at: datetime
    content_sha256: str


class ScoredChunk(BaseModel):
    model_config = ConfigDict(frozen=True)

    chunk: Chunk
    score: float


def content_digest(tenant_id: str, source: str, text: str) -> str:
    """Digest binds text to its tenant and source so a chunk cannot be moved."""
    return sha256_hex({"tenant_id": tenant_id, "source": source, "text": text})


class TenantVectorStore:
    """In-memory reference implementation of a partitioned vector index."""

    def __init__(self, embedder: Embedder) -> None:
        self._embedder = embedder
        self._partitions: dict[str, dict[str, tuple[Chunk, list[float]]]] = {}

    def upsert(
        self,
        identity: UserIdentity,
        *,
        chunk_id: str,
        text: str,
        source: str,
        allowed_roles: frozenset[str] = frozenset(),
    ) -> Chunk:
        """Store a chunk in the caller's own tenant partition."""
        chunk = Chunk(
            chunk_id=chunk_id,
            tenant_id=identity.tenant_id,
            text=text,
            source=source,
            allowed_roles=allowed_roles,
            ingested_by=identity.subject,
            ingested_at=datetime.now(UTC),
            content_sha256=content_digest(identity.tenant_id, source, text),
        )
        partition = self._partitions.setdefault(identity.tenant_id, {})
        partition[chunk_id] = (chunk, self._embedder.embed(text))
        return chunk

    def query(
        self, identity: UserIdentity, question: str, top_k: int = DEFAULT_TOP_K
    ) -> list[ScoredChunk]:
        """Nearest neighbours within the caller's tenant and role scope only."""
        limit = max(1, min(top_k, MAX_TOP_K))
        query_vector = self._embedder.embed(question)
        partition = self._partitions.get(identity.tenant_id, {})
        scored = [
            ScoredChunk(chunk=chunk, score=cosine_similarity(query_vector, vector))
            for chunk, vector in partition.values()
            if _role_permits(chunk, identity)
        ]
        scored.sort(key=lambda item: (-item.score, item.chunk.chunk_id))
        return scored[:limit]

    def tamper_for_test(self, tenant_id: str, chunk_id: str, new_text: str) -> None:
        """Simulate an attacker with write access to the index (lab only)."""
        chunk, vector = self._partitions[tenant_id][chunk_id]
        self._partitions[tenant_id][chunk_id] = (
            chunk.model_copy(update={"text": new_text}),
            vector,
        )


def _role_permits(chunk: Chunk, identity: UserIdentity) -> bool:
    """An empty role set means "any member of the tenant"."""
    return not chunk.allowed_roles or bool(chunk.allowed_roles & identity.roles)
