"""Command-line interface for iptable-lite."""

from __future__ import annotations

import argparse
import ipaddress
import logging
import sys
from dataclasses import replace
from pathlib import Path

from iptable_lite.engine import Firewall
from iptable_lite.events import EventEmitter
from iptable_lite.events import configure as configure_events
from iptable_lite.hashlimit import HashLimitTable
from iptable_lite.packet import FragmentError, PacketParseError, parse_ipv4
from iptable_lite.rules import ParseError, RuleSet, load_rules
from iptable_lite.scan import (
    DEFAULT_SCAN_BLOCK,
    DEFAULT_SCAN_MAX_SOURCES,
    DEFAULT_SCAN_PORTS,
    DEFAULT_SCAN_WINDOW,
    ScanDetector,
)
from iptable_lite.state import DEFAULT_MAX_ENTRIES, DEFAULT_TIMEOUT, StateTable
from iptable_lite.verdicts import configure as configure_logging
from iptable_lite.verdicts import log_drop

startup_logger = logging.getLogger("iptable_lite.cli")


def _queue_spec(value: str) -> tuple[str, int]:
    chain, separator, number = value.partition("=")
    if not separator or not chain or not number:
        raise argparse.ArgumentTypeError("queue must look like CHAIN=NUM")
    try:
        queue_num = int(number)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid queue number {number!r}") from exc
    if queue_num < 0:
        raise argparse.ArgumentTypeError("queue number must not be negative")
    return chain, queue_num


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iptable-lite",
        description="Small stateful packet filter inspired by iptables.",
    )
    parser.add_argument(
        "--rules",
        required=True,
        metavar="FILE",
        help="plain-text rule file (iptables/iptables-save syntax)",
    )
    parser.add_argument(
        "--queue",
        action="append",
        type=_queue_spec,
        default=None,
        metavar="CHAIN=NUM",
        help="run a chain on an NFQUEUE number; repeatable (e.g. INPUT=0)",
    )
    parser.add_argument(
        "--queue-num",
        type=int,
        default=0,
        metavar="N",
        help="NFQUEUE number to bind to (default: 0)",
    )
    parser.add_argument(
        "--chain",
        default=None,
        metavar="CHAIN",
        help="chain the captured packets belong to (default: packet's chain, INPUT)",
    )
    parser.add_argument(
        "--state-timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        metavar="SECONDS",
        help=f"idle seconds before a state entry expires (default: {DEFAULT_TIMEOUT:g})",
    )
    parser.add_argument(
        "--state-max-entries",
        type=int,
        default=DEFAULT_MAX_ENTRIES,
        metavar="N",
        help=f"maximum live state entries (default: {DEFAULT_MAX_ENTRIES})",
    )
    parser.add_argument(
        "--no-stateful",
        action="store_true",
        help="disable connection tracking (state matches will never fire)",
    )
    parser.add_argument(
        "--default-policy",
        choices=["ACCEPT", "DROP"],
        default="ACCEPT",
        help="policy for chains the rule file does not declare (default: ACCEPT)",
    )
    parser.add_argument(
        "--check",
        metavar="FILE",
        help="offline mode: verdicts for hex-encoded packets listed in FILE, one per line",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="verdict log level (default: INFO)",
    )
    parser.add_argument(
        "--alert-file",
        metavar="PATH",
        default=None,
        help="append alert events to PATH",
    )
    parser.add_argument(
        "--event-throttle",
        type=float,
        default=10.0,
        metavar="SECONDS",
        help="minimum seconds between repeated events of the same type/key (default: 10)",
    )
    parser.add_argument(
        "--scan-detect",
        action="store_true",
        help="enable port-scan detection and temporary source blocks",
    )
    parser.add_argument(
        "--scan-ports",
        type=int,
        default=DEFAULT_SCAN_PORTS,
        metavar="N",
        help=f"distinct destinations that trigger a scan alert (default: {DEFAULT_SCAN_PORTS})",
    )
    parser.add_argument(
        "--scan-window",
        type=float,
        default=DEFAULT_SCAN_WINDOW,
        metavar="SECONDS",
        help=f"sliding window for scan counting (default: {DEFAULT_SCAN_WINDOW:g})",
    )
    parser.add_argument(
        "--scan-block",
        type=float,
        default=DEFAULT_SCAN_BLOCK,
        metavar="SECONDS",
        help=f"temporary block duration (default: {DEFAULT_SCAN_BLOCK:g})",
    )
    parser.add_argument(
        "--scan-max-sources",
        type=int,
        default=DEFAULT_SCAN_MAX_SOURCES,
        metavar="N",
        help=f"maximum tracked scan sources (default: {DEFAULT_SCAN_MAX_SOURCES})",
    )
    parser.add_argument(
        "--scan-exempt",
        action="append",
        default=[],
        metavar="CIDR",
        help="source CIDR never counted or blocked; repeatable",
    )
    return parser


def _drop_malformed(
    events: EventEmitter, path: str, line_number: int, data: bytes, exc: Exception
) -> None:
    if isinstance(exc, FragmentError):
        event_type = "fragment_dropped"
        reason = f"fragment: {exc}"
        src = exc.src or "-"
    else:
        event_type = "malformed_packet"
        reason = f"malformed packet: {exc}"
        src = "-"
    log_drop(reason, "?", f"{len(data)} raw bytes")
    events.emit(event_type, src, detail=str(exc), key=src)
    print(f"DROP\t{path}:{line_number} {len(data)} raw bytes\t{reason}")


def check_mode(
    firewall: Firewall,
    path: str,
    chain: str | None,
    events: EventEmitter | None = None,
) -> int:
    """Filter a file of hex-encoded packets without needing root (FR-10)."""
    emitter = events if events is not None else firewall.events
    verdicts_seen = []
    for line_number, raw_line in enumerate(
        Path(path).read_text().splitlines(), start=1
    ):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            data = bytes.fromhex(line)
        except ValueError as exc:
            print(f"{path}:{line_number}: invalid hex: {exc}", file=sys.stderr)
            return 2
        try:
            packet = parse_ipv4(data)
        except PacketParseError as exc:
            _drop_malformed(emitter, path, line_number, data, exc)
            verdicts_seen.append("DROP")
            continue
        evaluation = firewall.evaluate(packet, chain)
        verdicts_seen.append(evaluation.verdict)
        print(f"{evaluation.verdict}\t{packet.five_tuple}\t{evaluation.reason}")
    print(f"# {len(verdicts_seen)} packet(s), verdicts: {' '.join(verdicts_seen) or '-'}")
    return 0


def build_state_table(args: argparse.Namespace) -> StateTable | None:
    if args.no_stateful:
        return None
    return StateTable(
        timeout=args.state_timeout, max_entries=args.state_max_entries
    )


def _validate_scan_args(args: argparse.Namespace) -> None:
    if args.scan_ports < 1:
        raise ValueError("scan port threshold must be positive")
    if args.scan_window <= 0:
        raise ValueError("scan window must be positive")
    if args.scan_block <= 0:
        raise ValueError("scan block must be positive")
    if args.scan_max_sources < 1:
        raise ValueError("scan max sources must be positive")
    for cidr in args.scan_exempt:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid --scan-exempt CIDR {cidr!r}") from exc
        if network.version != 4:
            raise ValueError("--scan-exempt only supports IPv4")


def _apply_default_policy(
    ruleset: RuleSet, policy: str, chains: set[str]
) -> RuleSet:
    for chain in sorted(chains):
        if chain not in ruleset.policies:
            startup_logger.warning(
                "chain %s is not declared; using --default-policy %s",
                chain,
                policy,
            )
    return replace(ruleset, fallback_policy=policy)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(getattr(logging, args.log_level))
    configure_events()

    try:
        _validate_scan_args(args)
        state_table = build_state_table(args)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    try:
        ruleset = load_rules(args.rules)
    except FileNotFoundError:
        print(f"rule file not found: {args.rules}", file=sys.stderr)
        return 2
    except ParseError as exc:
        print(f"{args.rules}: {exc}", file=sys.stderr)
        return 2

    queue_mappings = args.queue
    if queue_mappings:
        active_chains = {chain for chain, _ in queue_mappings}
    else:
        active_chains = {args.chain or "INPUT"}
    active_chains.update(rule.chain for rule in ruleset.rules)
    ruleset = _apply_default_policy(
        ruleset, args.default_policy, active_chains
    )

    events = EventEmitter(
        throttle=args.event_throttle, alert_file=args.alert_file
    )
    scan_detector = None
    if args.scan_detect:
        scan_detector = ScanDetector(
            ports=args.scan_ports,
            window=args.scan_window,
            block=args.scan_block,
            max_sources=args.scan_max_sources,
            exempt=args.scan_exempt,
            events=events,
        )

    firewall = Firewall(
        ruleset,
        state_table=state_table,
        hashlimit_table=HashLimitTable(),
        events=events,
        scan_detector=scan_detector,
    )

    if args.check is not None:
        check_chain = args.chain
        if check_chain is None and queue_mappings and len(queue_mappings) == 1:
            check_chain = queue_mappings[0][0]
        if check_chain is None and queue_mappings and len(queue_mappings) > 1:
            print(
                "--check needs --chain when several --queue mappings are used",
                file=sys.stderr,
            )
            return 2
        try:
            return check_mode(firewall, args.check, check_chain, events)
        except OSError as exc:
            print(f"cannot read {args.check}: {exc}", file=sys.stderr)
            return 2

    from iptable_lite.nfqueue_source import run_queue, run_queues

    try:
        if queue_mappings:
            run_queues(queue_mappings, firewall)
        else:
            run_queue(args.queue_num, firewall, args.chain)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
