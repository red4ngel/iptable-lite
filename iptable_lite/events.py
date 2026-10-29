"""Security events and alerts (FR-12, FR-13).

Events are deliberately separate from verdict logging: they never add a
verdict line.  Each line has the stable shape::

    event=<type> severity=<info|warn|alert> src=<ip> detail=<...>

Alerts are mirrored to ``iptable_lite.alerts`` and, optionally, an alert file.
"""

from __future__ import annotations

import logging
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable

EVENT_LOGGER_NAME = "iptable_lite.events"
ALERT_LOGGER_NAME = "iptable_lite.alerts"

SEVERITIES = {
    "malformed_packet": "warn",
    "fragment_dropped": "warn",
    "rate_limit_hit": "warn",
    "evaluation_error": "alert",
    "state_table_full": "alert",
    "hashlimit_table_full": "alert",
    "scan_detected": "alert",
    "scan_block_expired": "info",
}

DEFAULT_THROTTLE_SECONDS = 10.0
DEFAULT_THROTTLE_MEMORY = 4096

event_logger = logging.getLogger(EVENT_LOGGER_NAME)
alert_logger = logging.getLogger(ALERT_LOGGER_NAME)


@dataclass
class _ThrottleState:
    last_emitted: float
    suppressed: int = 0


class EventEmitter:
    """Emit throttled structured events and mirror alerts."""

    def __init__(
        self,
        throttle: float = DEFAULT_THROTTLE_SECONDS,
        throttle_memory: int = DEFAULT_THROTTLE_MEMORY,
        alert_file: str | None = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.throttle = max(0.0, float(throttle))
        self.throttle_memory = max(1, int(throttle_memory))
        self.alert_file = alert_file
        self._clock = clock
        self._throttle: OrderedDict[tuple[str, str], _ThrottleState] = OrderedDict()

    def __len__(self) -> int:
        return len(self._throttle)

    def emit(
        self,
        event_type: str,
        src: str,
        detail: str = "",
        key: str | None = None,
        severity: str | None = None,
    ) -> bool:
        """Emit one event unless it is throttled; return whether it was logged."""
        severity = severity or SEVERITIES.get(event_type, "warn")
        throttle_key = (event_type, key if key is not None else src)
        now = self._clock()

        suppressed = 0
        if self.throttle > 0:
            state = self._throttle.get(throttle_key)
            if state is not None and now - state.last_emitted < self.throttle:
                state.suppressed += 1
                self._throttle.move_to_end(throttle_key)
                return False
            if state is not None:
                suppressed = state.suppressed
                state.last_emitted = now
                state.suppressed = 0
                self._throttle.move_to_end(throttle_key)
            else:
                self._make_room(now)
                self._throttle[throttle_key] = _ThrottleState(last_emitted=now)

        line = (
            f"event={event_type} severity={severity} "
            f"src={src or '-'} detail={detail}"
        )
        if suppressed:
            line += f" suppressed={suppressed}"
        event_logger.warning(line)

        if severity == "alert":
            alert_logger.warning(line)
            self._append_alert(line)
        return True

    def _make_room(self, now: float) -> None:
        if len(self._throttle) < self.throttle_memory:
            return
        expired = [
            key
            for key, state in self._throttle.items()
            if now - state.last_emitted >= self.throttle
        ]
        for key in expired:
            del self._throttle[key]
        while len(self._throttle) >= self.throttle_memory:
            self._throttle.popitem(last=False)

    def _append_alert(self, line: str) -> None:
        if not self.alert_file:
            return
        try:
            with open(self.alert_file, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        except OSError:
            # An unwritable alert log must never change a packet verdict.
            pass


def configure(level: int = logging.WARNING) -> None:
    """Attach stderr handlers for the event and alert loggers."""
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    for logger in (event_logger, alert_logger):
        if not logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        logger.setLevel(level)
        logger.propagate = False
