"""Verdict logging for observability (FR-10)."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from iptable_lite.engine import Evaluation
    from iptable_lite.packet import Packet

LOGGER_NAME = "iptable_lite.verdict"

logger = logging.getLogger(LOGGER_NAME)


def log_verdict(evaluation: "Evaluation", packet: "Packet", chain: str) -> None:
    """Emit one structured line describing a packet's verdict."""
    state = packet.state if packet.state is not None else "-"
    logger.info(
        "verdict=%s chain=%s packet=%r state=%s reason=%s",
        evaluation.verdict,
        chain,
        packet.five_tuple,
        state,
        evaluation.reason,
    )


def configure(level: int = logging.INFO) -> logging.Logger:
    """Attach a stderr handler so verdicts are visible without extra setup."""
    target = logging.getLogger(LOGGER_NAME)
    if not target.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        )
        target.addHandler(handler)
    target.setLevel(level)
    target.propagate = False
    return target
