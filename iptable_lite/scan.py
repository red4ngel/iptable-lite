"""Port-scan detection and per-source temporary blocks (FR-14)."""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable

from iptable_lite.events import EventEmitter
from iptable_lite.packet import Packet

DEFAULT_SCAN_PORTS = 10
DEFAULT_SCAN_WINDOW = 10.0
DEFAULT_SCAN_BLOCK = 60.0
DEFAULT_SCAN_MAX_SOURCES = 4096


@dataclass
class _SourceRecord:
    destinations: dict[tuple[str, str, int | None], float] = field(
        default_factory=dict
    )
    last_seen: float = 0.0


class ScanDetector:
    """Count distinct destinations per source and temporarily block scanners."""

    def __init__(
        self,
        ports: int = DEFAULT_SCAN_PORTS,
        window: float = DEFAULT_SCAN_WINDOW,
        block: float = DEFAULT_SCAN_BLOCK,
        max_sources: int = DEFAULT_SCAN_MAX_SOURCES,
        exempt: Iterable[str] = (),
        clock: Callable[[], float] = time.monotonic,
        events: EventEmitter | None = None,
        enabled: bool = True,
    ):
        if ports < 1:
            raise ValueError("scan port threshold must be positive")
        if window <= 0:
            raise ValueError("scan window must be positive")
        if block <= 0:
            raise ValueError("scan block must be positive")
        if max_sources < 1:
            raise ValueError("scan max sources must be positive")
        self.ports = ports
        self.window = window
        self.block = block
        self.max_sources = max_sources
        self.enabled = enabled
        self._clock = clock
        self.events = events or EventEmitter(clock=clock)
        self._exempt = tuple(
            ipaddress.ip_network(value, strict=False) for value in exempt
        )
        self._records: dict[str, _SourceRecord] = {}
        self._blocked: dict[str, float] = {}

    def __len__(self) -> int:
        return len(self._records) + len(self._blocked)

    def _is_exempt(self, src: str) -> bool:
        address = ipaddress.ip_address(src)
        return any(address in network for network in self._exempt)

    def blocked(self, src: str) -> bool:
        """Return True while ``src`` is blocked; expire lazily when it ends."""
        if not self.enabled:
            return False
        now = self._clock()
        self._expire_blocks(now)
        return src in self._blocked

    def observe(self, packet: Packet) -> bool:
        """Count a NEW TCP/UDP packet; return True when it triggers a block."""
        if not self.enabled:
            return False
        # With --no-stateful the firewall leaves state unset; such packets
        # are still new for scan accounting because no tracked flow exists.
        if packet.protocol not in ("tcp", "udp") or packet.state not in (None, "NEW"):
            return False
        if self._is_exempt(packet.src):
            return False

        now = self._clock()
        self._expire_blocks(now)
        if packet.src in self._blocked:
            return False

        record = self._records.get(packet.src)
        if record is None:
            self._make_room_for_source(now)
            if len(self._records) + len(self._blocked) >= self.max_sources:
                # All capacity is held by active blocks; never evict those.
                return False
            record = _SourceRecord()
            self._records[packet.src] = record

        record.last_seen = now
        key = (packet.dst, packet.protocol, packet.dport)
        record.destinations[key] = now
        self._purge_window(record, now)

        if len(record.destinations) >= self.ports:
            del self._records[packet.src]
            self._block_source(packet.src, now)
            self.events.emit(
                "scan_detected",
                packet.src,
                detail=(
                    f"distinct={len(record.destinations)} "
                    f"dst={packet.dst} proto={packet.protocol} "
                    f"dport={packet.dport} block={self.block:g}s"
                ),
                key=packet.src,
            )
            return True
        return False

    def _purge_window(self, record: _SourceRecord, now: float) -> None:
        stale = [
            key
            for key, seen in record.destinations.items()
            if now - seen >= self.window
        ]
        for key in stale:
            del record.destinations[key]

    def _make_room_for_source(self, now: float) -> None:
        if len(self._records) + len(self._blocked) < self.max_sources:
            return
        if not self._records:
            return
        oldest = min(self._records, key=lambda src: self._records[src].last_seen)
        del self._records[oldest]

    def _block_source(self, src: str, now: float) -> None:
        if len(self._blocked) >= self.max_sources:
            # Keep all existing active blocks; refuse to grow without bound.
            return
        self._blocked[src] = now + self.block

    def _expire_blocks(self, now: float) -> None:
        expired = [src for src, until in self._blocked.items() if now >= until]
        for src in expired:
            del self._blocked[src]
            self.events.emit(
                "scan_block_expired",
                src,
                detail=f"block={self.block:g}s",
                key=src,
            )

    def is_blocked(self, src: str) -> bool:
        """Compatibility alias for :meth:`blocked`."""
        return self.blocked(src)
