"""Rule matching and per-packet verdicts (FR-2, FR-3, FR-5)."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path

from iptable_lite.events import EventEmitter
from iptable_lite.hashlimit import HashLimitTable
from iptable_lite.packet import Packet
from iptable_lite.ratelimit import RateLimiter
from iptable_lite.rules import Rule, RuleSet, load_rules
from iptable_lite.state import StateTable
from iptable_lite.verdicts import log_verdict

ACCEPT = "ACCEPT"
DROP = "DROP"


@dataclass(frozen=True)
class Evaluation:
    """The single verdict for a packet plus why it was chosen (FR-3)."""

    verdict: str
    rule: Rule | None = None
    used_default_policy: bool = False
    reason_override: str | None = None

    @property
    def reason(self) -> str:
        if self.reason_override is not None:
            return self.reason_override
        if self.rule is not None:
            return f"rule[{self.rule.index}] {self.rule.raw}"
        return "default policy"


def _field_matches(matched: bool, negated: bool) -> bool:
    return matched != negated


def _network_matches(network: str, address: str) -> bool:
    return ipaddress.ip_address(address) in ipaddress.ip_network(network)


def _port_matches(bounds: tuple[int, int], port: int | None) -> bool:
    if port is None:
        return False
    low, high = bounds
    return low <= port <= high


def _emit_rate_limit_hit(
    events: EventEmitter | None, packet: Packet, detail: str, key: str
) -> None:
    if events is not None:
        events.emit("rate_limit_hit", packet.src, detail=detail, key=key)


def rule_matches(
    rule: Rule,
    packet: Packet,
    rate_limiter: RateLimiter | None = None,
    hashlimit_table: HashLimitTable | None = None,
    events: EventEmitter | None = None,
) -> bool:
    """Evaluate one rule's match specification against a packet (FR-4)."""
    match = rule.match
    negated = match.negated

    if match.src is not None:
        matched = _network_matches(match.src, packet.src)
        if not _field_matches(matched, "src" in negated):
            return False
    elif "src" in negated:
        return False

    if match.dst is not None:
        matched = _network_matches(match.dst, packet.dst)
        if not _field_matches(matched, "dst" in negated):
            return False
    elif "dst" in negated:
        return False

    if match.protocol is not None:
        matched = packet.protocol == match.protocol
        if not _field_matches(matched, "protocol" in negated):
            return False
    elif "protocol" in negated:
        return False

    if match.sport is not None:
        matched = _port_matches(match.sport, packet.sport)
        if not _field_matches(matched, "sport" in negated):
            return False
    elif "sport" in negated:
        return False

    if match.dport is not None:
        matched = _port_matches(match.dport, packet.dport)
        if not _field_matches(matched, "dport" in negated):
            return False
    elif "dport" in negated:
        return False

    if match.states is not None:
        has_state = packet.state is not None and packet.state in match.states
        if not _field_matches(has_state, "states" in negated):
            return False
    elif "states" in negated:
        return False

    # Rate limiting is checked last so packets the rule does not otherwise
    # match never spend tokens.
    if match.limit is not None and rate_limiter is not None:
        if not rate_limiter.allow(
            rule, match.limit.rate_per_second, match.limit.burst
        ):
            _emit_rate_limit_hit(
                events,
                packet,
                detail=(
                    f"rule={rule.index} limit="
                    f"{match.limit.rate_per_second:g}/s "
                    f"burst={match.limit.burst}"
                ),
                key=f"rule:{rule.index}",
            )
            return False

    if match.hashlimit is not None and hashlimit_table is not None:
        result = hashlimit_table.check(match.hashlimit, packet)
        spec = match.hashlimit
        if result.table_full and events is not None:
            events.emit(
                "hashlimit_table_full",
                packet.src,
                detail=f"name={spec.name} max={spec.max_entries}",
                key=spec.name,
            )
        if result.exhausted:
            _emit_rate_limit_hit(
                events,
                packet,
                detail=(
                    f"name={spec.name} "
                    f"{'above' if spec.above else 'upto'}="
                    f"{spec.rate_per_second:g}/s burst={spec.burst}"
                ),
                key=spec.name,
            )
        if not result.match:
            return False

    return True


class Firewall:
    """Applies a rule set to packets, first match wins (FR-2)."""

    def __init__(
        self,
        ruleset: RuleSet,
        state_table: StateTable | None = None,
        rate_limiter: RateLimiter | None = None,
        hashlimit_table: HashLimitTable | None = None,
        events: EventEmitter | None = None,
        scan_detector=None,
    ):
        self.ruleset = ruleset
        self.state_table = state_table
        self.rate_limiter = rate_limiter if rate_limiter is not None else RateLimiter()
        self.hashlimit_table = (
            hashlimit_table if hashlimit_table is not None else HashLimitTable()
        )
        self.events = events if events is not None else EventEmitter()
        self.scan_detector = scan_detector
        if self.scan_detector is not None and self.scan_detector.events is None:
            self.scan_detector.events = self.events

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        state_table: StateTable | None = None,
        rate_limiter: RateLimiter | None = None,
        hashlimit_table: HashLimitTable | None = None,
        events: EventEmitter | None = None,
        scan_detector=None,
    ) -> "Firewall":
        return cls(
            load_rules(path),
            state_table=state_table,
            rate_limiter=rate_limiter,
            hashlimit_table=hashlimit_table,
            events=events,
            scan_detector=scan_detector,
        )

    def _decide(self, packet: Packet, chain: str) -> tuple[Packet, Evaluation]:
        detector = self.scan_detector
        if detector is not None and detector.blocked(packet.src):
            return packet, Evaluation(
                verdict=DROP,
                reason_override=f"source blocked by scan detection: {packet.src}",
            )

        if self.state_table is not None:
            packet = self.state_table.annotate(packet)

        if detector is not None and detector.observe(packet):
            return packet, Evaluation(
                verdict=DROP,
                reason_override=f"scan detected: {packet.src}",
            )

        evaluation = None
        for rule in self.ruleset.rules:
            if rule.chain == chain and rule_matches(
                rule,
                packet,
                self.rate_limiter,
                self.hashlimit_table,
                self.events,
            ):
                evaluation = Evaluation(verdict=rule.target, rule=rule)
                break
        if evaluation is None:
            evaluation = Evaluation(
                verdict=self.ruleset.default_policy(chain),
                rule=None,
                used_default_policy=True,
            )

        if evaluation.verdict == ACCEPT and self.state_table is not None:
            if not self.state_table.commit(packet):
                self.events.emit(
                    "state_table_full",
                    packet.src,
                    detail=(
                        f"entries={self.state_table.max_entries} "
                        f"timeout={self.state_table.timeout:g}s"
                    ),
                    key="state",
                )
        return packet, evaluation

    def evaluate(self, packet: Packet, chain: str | None = None) -> Evaluation:
        """Return the single verdict for ``packet`` in ``chain`` (FR-3).

        Every packet gets exactly one verdict log line (FR-10).  Connection
        state is classified read-only before matching and is committed only
        after an ACCEPT verdict.
        """
        chain = chain or packet.chain
        try:
            packet, evaluation = self._decide(packet, chain)
        except Exception as exc:  # never accept a packet we could not evaluate
            evaluation = Evaluation(
                verdict=DROP,
                reason_override=f"evaluation error: {type(exc).__name__}: {exc}",
            )
            self.events.emit(
                "evaluation_error",
                getattr(packet, "src", "-"),
                detail=f"{type(exc).__name__}: {exc}",
                key="evaluation",
            )
        log_verdict(evaluation, packet, chain)
        return evaluation

    def verdict(self, packet: Packet, chain: str | None = None) -> str:
        return self.evaluate(packet, chain).verdict
