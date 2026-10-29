"""Connection state table: NEW / ESTABLISHED tracking with idle expiry
(FR-6, FR-7, FR-8, FR-9)."""

from __future__ import annotations

import time
from dataclasses import dataclass, replace
from typing import Callable

from iptable_lite.packet import Packet

STATE_NEW = "NEW"
STATE_ESTABLISHED = "ESTABLISHED"

DEFAULT_TIMEOUT = 300.0
DEFAULT_MAX_ENTRIES = 65536


@dataclass(frozen=True)
class FlowKey:
    """Direction-agnostic key so both directions share one entry."""

    endpoint_a: tuple[str, int]
    endpoint_b: tuple[str, int]
    protocol: str

    @classmethod
    def of(cls, packet: Packet) -> "FlowKey":
        source = (packet.src, packet.sport if packet.sport is not None else -1)
        destination = (packet.dst, packet.dport if packet.dport is not None else -1)
        first, second = sorted((source, destination))
        return cls(endpoint_a=first, endpoint_b=second, protocol=packet.protocol)


@dataclass
class ConnectionEntry:
    created_at: float
    last_seen: float
    packets: int = 1


class StateTable:
    """Tracks flows seen by the filter (FR-6) and expires idle ones (FR-8)."""

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        clock: Callable[[], float] = time.monotonic,
        max_entries: int = DEFAULT_MAX_ENTRIES,
    ):
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if max_entries < 1:
            raise ValueError("max_entries must be positive")
        self.timeout = timeout
        self.max_entries = max_entries
        self._clock = clock
        self._entries: dict[FlowKey, ConnectionEntry] = {}

    def __len__(self) -> int:
        return len(self._entries)

    def expire(self, now: float | None = None) -> int:
        """Drop entries idle for longer than the timeout; return how many."""
        now = self._clock() if now is None else now
        stale = [
            key
            for key, entry in self._entries.items()
            if now - entry.last_seen >= self.timeout
        ]
        for key in stale:
            del self._entries[key]
        return len(stale)

    def observe(self, packet: Packet) -> str:
        """Record ``packet`` and return its connection state (FR-7)."""
        now = self._clock()
        self.expire(now)
        key = FlowKey.of(packet)
        entry = self._entries.get(key)
        if entry is None:
            if len(self._entries) >= self.max_entries:
                return STATE_NEW
            self._entries[key] = ConnectionEntry(created_at=now, last_seen=now)
            return STATE_NEW
        entry.last_seen = now
        entry.packets += 1
        return STATE_ESTABLISHED

    def classify(self, packet: Packet) -> str:
        """Classify without creating or refreshing any entry (read-only)."""
        now = self._clock()
        self.expire(now)
        return (
            STATE_ESTABLISHED
            if FlowKey.of(packet) in self._entries
            else STATE_NEW
        )

    def annotate(self, packet: Packet) -> Packet:
        """Return ``packet`` with its connection state filled in (FR-9).

        Classification is read-only: a packet that is later dropped cannot
        create or refresh state.
        """
        if packet.state is not None:
            return packet
        return replace(packet, state=self.classify(packet))

    def commit(self, packet: Packet) -> bool:
        """Record a packet's flow after an ACCEPT verdict.

        Returns ``False`` when the table is full after purging expired entries,
        in which case the flow is not tracked.  Live entries are never evicted.
        """
        now = self._clock()
        self.expire(now)
        key = FlowKey.of(packet)
        entry = self._entries.get(key)
        if entry is not None:
            entry.last_seen = now
            entry.packets += 1
            return True
        if len(self._entries) >= self.max_entries:
            return False
        self._entries[key] = ConnectionEntry(created_at=now, last_seen=now)
        return True

    def state_of(self, packet: Packet) -> str | None:
        """Look up a packet's state without creating a new entry."""
        entry = self._entries.get(FlowKey.of(packet))
        if entry is None:
            return None
        return STATE_ESTABLISHED
