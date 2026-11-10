"""Embedding interface plus a deterministic embedder for tests and the lab.

Production deployments plug in a real model through the ``Embedder``
protocol; the guard logic never depends on embedding quality.
"""

from __future__ import annotations

import hashlib
import math
import re
from typing import Protocol

DEFAULT_DIMENSIONS = 256
_TOKEN = re.compile(r"[a-z0-9]+")


class Embedder(Protocol):
    def embed(self, text: str) -> list[float]: ...


class HashingEmbedder:
    """Bag-of-words feature hashing: no model, no network, fully repeatable."""

    def __init__(self, dimensions: int = DEFAULT_DIMENSIONS) -> None:
        if dimensions <= 0:
            raise ValueError("dimensions must be positive")
        self._dimensions = dimensions

    def embed(self, text: str) -> list[float]:
        vector = [0.0] * self._dimensions
        for token in _TOKEN.findall(text.lower()):
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            vector[int.from_bytes(digest[:4], "big") % self._dimensions] += 1.0
        norm = math.sqrt(sum(value * value for value in vector))
        return [value / norm for value in vector] if norm else vector


def cosine_similarity(left: list[float], right: list[float]) -> float:
    """Cosine similarity; zero vectors compare as 0 rather than dividing by zero."""
    if len(left) != len(right):
        raise ValueError("embedding dimensions differ")
    dot = sum(a * b for a, b in zip(left, right, strict=True))
    norms = math.sqrt(sum(a * a for a in left)) * math.sqrt(sum(b * b for b in right))
    return dot / norms if norms else 0.0
