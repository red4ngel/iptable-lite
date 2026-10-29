"""Per-rule token-bucket rate limiting (``-m limit``).

Each limited rule gets its own bucket: it starts full with ``burst`` tokens,
one token is spent per matching packet, and tokens refill at ``rate`` per
second up to the burst size.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Hashable

DEFAULT_RATE = 3 / 3600  # iptables' default: 3/hour
DEFAULT_BURST = 5


@dataclass
class _Bucket:
    tokens: float
    last_refill: float
    rate: float
    burst: int


class RateLimiter:
    """Token buckets keyed by rule so each rule limits independently."""

    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._buckets: dict[Hashable, _Bucket] = {}

    def __len__(self) -> int:
        return len(self._buckets)

    def tokens(self, key: Hashable) -> float | None:
        """Current token count for ``key`` (None if it has no bucket yet)."""
        bucket = self._buckets.get(key)
        if bucket is None:
            return None
        self._refill(bucket, self._clock())
        return bucket.tokens

    def allow(self, key: Hashable, rate_per_second: float, burst: int) -> bool:
        """Spend one token for ``key``; return False when the budget is empty."""
        if rate_per_second <= 0:
            raise ValueError("rate must be positive")
        if burst < 1:
            raise ValueError("burst must be at least 1")

        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = _Bucket(
                tokens=float(burst),
                last_refill=self._clock(),
                rate=rate_per_second,
                burst=burst,
            )
            self._buckets[key] = bucket
        else:
            bucket.rate = rate_per_second
            bucket.burst = burst
            self._refill(bucket, self._clock())

        if bucket.tokens < 1.0:
            return False
        bucket.tokens -= 1.0
        return True

    @staticmethod
    def _refill(bucket: _Bucket, now: float) -> None:
        elapsed = max(0.0, now - bucket.last_refill)
        bucket.tokens = min(float(bucket.burst), bucket.tokens + elapsed * bucket.rate)
        bucket.last_refill = now
