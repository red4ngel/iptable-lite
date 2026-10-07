"""Live packet source: NFQUEUE userspace capture (Technical Requirements).

Requires the optional ``NetfilterQueue`` dependency and a Linux box with a
rule such as::

    iptables -A INPUT -j NFQUEUE --queue-num 0
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from iptable_lite.engine import ACCEPT, Firewall
from iptable_lite.packet import PacketParseError, parse_ipv4

QUEUE_CALLBACK = Callable[[Any], None]

logger = logging.getLogger("iptable_lite.verdict")


def _chain_of(packet, chain: str | None) -> str:
    return chain if chain is not None else packet.chain


def make_callback(firewall: Firewall, chain: str | None = None) -> QUEUE_CALLBACK:
    """Build the NFQUEUE callback that turns packets into verdicts.

    Malformed packets cannot be matched against rules, so they are dropped
    and logged (FR-3, FR-10).
    """

    def callback(nf_packet: Any) -> None:
        raw = nf_packet.get_payload()
        try:
            packet = parse_ipv4(raw)
        except PacketParseError as exc:
            logger.info(
                "verdict=DROP chain=%s packet=%r state=- reason=malformed packet: %s",
                chain or "?",
                f"{len(raw)} raw bytes",
                exc,
            )
            nf_packet.drop()
            return

        evaluation = firewall.evaluate(packet, chain)
        if evaluation.verdict == ACCEPT:
            nf_packet.accept()
        else:
            nf_packet.drop()

    return callback


def run_queue(queue_num: int, firewall: Firewall, chain: str | None = None) -> None:
    """Bind to ``queue_num`` and filter packets until interrupted."""
    try:
        netfilter_queue = _load_netfilterqueue()
    except ImportError as exc:
        raise RuntimeError(
            "NetfilterQueue is required for live capture; "
            "install it with 'pip install NetfilterQueue' (Linux only)"
        ) from exc

    nfqueue = netfilter_queue()
    nfqueue.bind(queue_num, make_callback(firewall, chain))
    try:
        nfqueue.run()
    except KeyboardInterrupt:  # pragma: no cover - interactive
        pass
    finally:
        nfqueue.unbind()


def _load_netfilterqueue():
    """Import hook kept separate so tests can monkeypatch it."""
    from netfilterqueue import NetfilterQueue

    return NetfilterQueue
