"""Live packet source: NFQUEUE userspace capture (Technical Requirements).

Requires the optional ``NetfilterQueue`` dependency and a Linux box with a
rule such as::

    iptables -A INPUT -j NFQUEUE --queue-num 0
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Callable, Iterable

from iptable_lite.engine import ACCEPT, Firewall
from iptable_lite.events import EventEmitter
from iptable_lite.packet import FragmentError, PacketParseError, parse_ipv4

QUEUE_CALLBACK = Callable[[Any], None]

logger = logging.getLogger("iptable_lite.verdict")


def _chain_of(packet, chain: str | None) -> str:
    return chain if chain is not None else packet.chain


def _log_drop(chain: str | None, raw: bytes, reason: str) -> None:
    logger.info(
        "verdict=DROP chain=%s packet=%r state=- reason=%s",
        chain or "?",
        f"{len(raw)} raw bytes",
        reason,
    )


def make_callback(
    firewall: Firewall, chain: str | None = None, events: EventEmitter | None = None
) -> QUEUE_CALLBACK:
    """Build the NFQUEUE callback that turns packets into verdicts.

    Malformed and fragmented packets cannot be evaluated safely, so they are
    always dropped.  Unexpected errors are also converted into DROP verdicts.
    """
    emitter = events if events is not None else firewall.events

    def callback(nf_packet: Any) -> None:
        raw = b""
        try:
            raw = nf_packet.get_payload()
            try:
                packet = parse_ipv4(raw)
            except FragmentError as exc:
                _log_drop(chain, raw, f"fragment: {exc}")
                emitter.emit(
                    "fragment_dropped",
                    exc.src or "-",
                    detail=str(exc),
                    key=exc.src or "-",
                )
                nf_packet.drop()
                return
            except PacketParseError as exc:
                _log_drop(chain, raw, f"malformed packet: {exc}")
                emitter.emit(
                    "malformed_packet",
                    "-",
                    detail=str(exc),
                    key="malformed",
                )
                nf_packet.drop()
                return

            evaluation = firewall.evaluate(packet, chain)
            if evaluation.verdict == ACCEPT:
                nf_packet.accept()
            else:
                nf_packet.drop()
        except Exception as exc:  # never let a packet escape unhandled
            _log_drop(
                chain,
                raw if isinstance(raw, bytes) else b"",
                f"evaluation error: {type(exc).__name__}: {exc}",
            )
            emitter.emit(
                "evaluation_error",
                "-",
                detail=f"{type(exc).__name__}: {exc}",
                key="evaluation",
            )
            try:
                nf_packet.drop()
            except Exception:
                pass

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


def run_queues(
    mappings: Iterable[tuple[str, int]], firewall: Firewall
) -> None:
    """Run one shared firewall across several ``(chain, queue_num)`` pairs."""
    mappings = list(mappings)
    if not mappings:
        raise RuntimeError("at least one --queue CHAIN=NUM is required")
    if len(mappings) == 1:
        chain, queue_num = mappings[0]
        run_queue(queue_num, firewall, chain)
        return

    try:
        netfilter_queue = _load_netfilterqueue()
    except ImportError as exc:
        raise RuntimeError(
            "NetfilterQueue is required for live capture; "
            "install it with 'pip install NetfilterQueue' (Linux only)"
        ) from exc

    queues = []
    threads = []
    try:
        for chain, queue_num in mappings:
            nfqueue = netfilter_queue()
            nfqueue.bind(queue_num, make_callback(firewall, chain))
            queues.append(nfqueue)
            thread = threading.Thread(
                target=nfqueue.run, name=f"nfqueue-{queue_num}", daemon=True
            )
            threads.append(thread)
        for thread in threads:
            thread.start()
        for thread in threads:
            while thread.is_alive():
                thread.join(timeout=0.2)
    except KeyboardInterrupt:  # pragma: no cover - interactive
        pass
    finally:
        for nfqueue in queues:
            try:
                nfqueue.unbind()
            except Exception:
                pass


def _load_netfilterqueue():
    """Import hook kept separate so tests can monkeypatch it."""
    from netfilterqueue import NetfilterQueue

    return NetfilterQueue
