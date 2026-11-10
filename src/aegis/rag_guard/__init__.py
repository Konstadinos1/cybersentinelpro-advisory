"""Tenant-isolated RAG store and vector guard."""

from aegis.rag_guard.embedding import Embedder, HashingEmbedder, cosine_similarity
from aegis.rag_guard.guard import IngestionResult, RagGuard, RetrievalResult, spotlight
from aegis.rag_guard.store import Chunk, ScoredChunk, TenantVectorStore, content_digest

__all__ = [
    "Chunk",
    "Embedder",
    "HashingEmbedder",
    "IngestionResult",
    "RagGuard",
    "RetrievalResult",
    "ScoredChunk",
    "TenantVectorStore",
    "content_digest",
    "cosine_similarity",
    "spotlight",
]
