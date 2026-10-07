"""Command-line interface for iptable-lite."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from iptable_lite.engine import Firewall
from iptable_lite.packet import PacketParseError, parse_ipv4
from iptable_lite.rules import ParseError
from iptable_lite.state import DEFAULT_TIMEOUT, StateTable
from iptable_lite.verdicts import configure as configure_logging


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
        "--no-stateful",
        action="store_true",
        help="disable connection tracking (state matches will never fire)",
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
    return parser


def check_mode(firewall: Firewall, path: str, chain: str | None) -> int:
    """Filter a file of hex-encoded packets without needing root (FR-10)."""
    verdicts_seen = []
    for line_number, raw_line in enumerate(Path(path).read_text().splitlines(), start=1):
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
            print(f"{path}:{line_number}: unparsable packet: {exc}", file=sys.stderr)
            return 2
        evaluation = firewall.evaluate(packet, chain)
        verdicts_seen.append(evaluation.verdict)
        print(f"{evaluation.verdict}\t{packet.five_tuple}\t{evaluation.reason}")
    print(f"# {len(verdicts_seen)} packet(s), verdicts: {' '.join(verdicts_seen) or '-'}")
    return 0


def build_state_table(args: argparse.Namespace) -> StateTable | None:
    if args.no_stateful:
        return None
    return StateTable(timeout=args.state_timeout)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(getattr(logging, args.log_level))

    try:
        state_table = build_state_table(args)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    try:
        firewall = Firewall.from_file(args.rules, state_table=state_table)
    except FileNotFoundError:
        print(f"rule file not found: {args.rules}", file=sys.stderr)
        return 2
    except ParseError as exc:
        print(f"{args.rules}: {exc}", file=sys.stderr)
        return 2

    if args.check is not None:
        try:
            return check_mode(firewall, args.check, args.chain)
        except OSError as exc:
            print(f"cannot read {args.check}: {exc}", file=sys.stderr)
            return 2

    from iptable_lite.nfqueue_source import run_queue

    try:
        run_queue(args.queue_num, firewall, args.chain)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
