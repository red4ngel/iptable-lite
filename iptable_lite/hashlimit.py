"""Per-source/per-key token buckets for ``-m hashlimit`` (FR-11 extension)."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Hashable

from iptable_lite.packet import Packet

DEFAULT_HASHLIMIT_BURST = 5
DEFAULT_HASHLIMIT_MODE = ("srcip",)
DEFAULT_HASHLIMIT_MAX = 4096
DEFAULT_HASHLIMIT_EXPIRE_MS = 60000
VALID_HASHLIMIT_MODES = frozenset({"srcip", "dstip", "dstport"})


@dataclass(frozen=True)
class HashLimitSpec:
    """A parsed ``-m hashlimit`` specification."""

    name: str
    rate_per_second: float
    above: bool = False
    burst: int = DEFAULT_HASHLIMIT_BURST
    mode: tuple[str, ...] = DEFAULT_HASHLIMIT_MODE
    max_entries: int = DEFAULT_HASHLIMIT_MAX
    expire_ms: int = DEFAULT_HASHLIMIT_EXPIRE_MS

    @property
    def expire_seconds(self) -> float:
        return self.expire_ms / 1000.0


@dataclass
class _Bucket:
    tokens: float
    last_refill: float
    last_seen: float
    rate: float
    burst: int


@dataclass(frozen=True)
class HashLimitResult:
    match: bool
    exhausted: bool
    table_full: bool = False


class HashLimitTable:
    """Bounded hash tables of token buckets, one namespace per limit name."""

    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._tables: dict[str, dict[Hashable, _Bucket]] = {}

    def __len__(self) -> int:
        return sum(len(table) for table in self._tables.values())

    def bucket_count(self, name: str) -> int:
        return len(self._tables.get(name, {}))

    def check(self, spec: HashLimitSpec, packet: Packet) -> HashLimitResult:
        key = _key_for(spec.mode, packet)
        table = self._tables.setdefault(spec.name, {})
        now = self._clock()

        bucket = table.get(key)
        table_full = False
        if bucket is None:
            self._purge_idle(table, spec, now)
            if len(table) >= spec.max_entries:
                # A new key when the table is full counts as over the limit.
                # Existing (live) keys are never evicted.
                return HashLimitResult(
                    match=spec.above, exhausted=True, table_full=True
                )
            bucket = _Bucket(
                tokens=float(spec.burst),
                last_refill=now,
                last_seen=now,
                rate=spec.rate_per_second,
                burst=spec.burst,
            )
            table[key] = bucket
        else:
            bucket.rate = spec.rate_per_second
            bucket.burst = spec.burst
            _refill(bucket, now)
            bucket.last_seen = now

        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            exhausted = False
        else:
            exhausted = True
        return HashLimitResult(
            match=exhausted if spec.above else not exhausted,
            exhausted=exhausted,
            table_full=table_full,
        )

    @staticmethod
    def _purge_idle(
        table: dict[Hashable, _Bucket], spec: HashLimitSpec, now: float
    ) -> None:
        if not table:
            return
        expire = spec.expire_seconds
        stale = [
            key
            for key, bucket in table.items()
            if now - bucket.last_seen >= expire
        ]
        for key in stale:
            del table[key]


def _key_for(mode: tuple[str, ...], packet: Packet) -> tuple:
    values = []
    for part in mode:
        if part == "srcip":
            values.append(packet.src)
        elif part == "dstip":
            values.append(packet.dst)
        elif part == "dstport":
            values.append(packet.dport)
    return tuple(values)


def _refill(bucket: _Bucket, now: float) -> None:
    elapsed = max(0.0, now - bucket.last_refill)
    bucket.tokens = min(float(bucket.burst), bucket.tokens + elapsed * bucket.rate)
    bucket.last_refill = now
