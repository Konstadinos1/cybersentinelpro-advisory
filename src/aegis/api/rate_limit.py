"""In-memory sliding-window rate limiter for the public demo.

State lives in one process, so behind several instances each enforces its
own window. That is enough to stop a single client from turning the demo
into free compute; it is not a substitute for limits at the edge.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable

DEFAULT_MAX_TRACKED_KEYS = 10_000


class SlidingWindowLimiter:
    """Allows at most ``max_requests`` per key in any ``window_seconds`` span."""

    def __init__(
        self,
        max_requests: int,
        window_seconds: float,
        *,
        max_tracked_keys: int = DEFAULT_MAX_TRACKED_KEYS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_requests <= 0 or window_seconds <= 0 or max_tracked_keys <= 0:
            raise ValueError("limits must be positive")
        self._max_requests = max_requests
        self._window = window_seconds
        self._max_keys = max_tracked_keys
        self._clock = clock
        self._hits: dict[str, deque[float]] = {}
        # Sync FastAPI endpoints run on a thread pool.
        self._lock = threading.Lock()

    @property
    def window_seconds(self) -> float:
        return self._window

    def allow(self, key: str) -> bool:
        """Record a request for ``key``; False means the caller is over the limit."""
        now = self._clock()
        with self._lock:
            hits = self._hits.get(key)
            if hits is None:
                self._make_room(now)
                hits = self._hits[key] = deque()
            self._drop_expired(hits, now)
            if len(hits) >= self._max_requests:
                return False
            hits.append(now)
            return True

    def _drop_expired(self, hits: deque[float], now: float) -> None:
        while hits and now - hits[0] >= self._window:
            hits.popleft()

    def _make_room(self, now: float) -> None:
        """Bound memory: forget idle keys, then the least recently created."""
        if len(self._hits) < self._max_keys:
            return
        for key in [
            k for k, hits in self._hits.items() if not hits or now - hits[-1] >= self._window
        ]:
            del self._hits[key]
        while len(self._hits) >= self._max_keys:
            del self._hits[next(iter(self._hits))]
