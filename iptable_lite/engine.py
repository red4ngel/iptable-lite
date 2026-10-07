"""Rule matching and per-packet verdicts (FR-2, FR-3, FR-5)."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path

from iptable_lite.packet import Packet
from iptable_lite.rules import Rule, RuleSet, load_rules

ACCEPT = "ACCEPT"
DROP = "DROP"


@dataclass(frozen=True)
class Evaluation:
    """The single verdict for a packet plus why it was chosen (FR-3)."""

    verdict: str
    rule: Rule | None = None
    used_default_policy: bool = False

    @property
    def reason(self) -> str:
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


def rule_matches(rule: Rule, packet: Packet) -> bool:
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

    return True


class Firewall:
    """Applies a rule set to packets, first match wins (FR-2)."""

    def __init__(self, ruleset: RuleSet):
        self.ruleset = ruleset

    @classmethod
    def from_file(cls, path: str | Path) -> "Firewall":
        return cls(load_rules(path))

    def evaluate(self, packet: Packet, chain: str | None = None) -> Evaluation:
        """Return the single verdict for ``packet`` in ``chain`` (FR-3)."""
        chain = chain or packet.chain
        for rule in self.ruleset.rules:
            if rule.chain == chain and rule_matches(rule, packet):
                return Evaluation(verdict=rule.target, rule=rule)
        return Evaluation(
            verdict=self.ruleset.default_policy(chain),
            rule=None,
            used_default_policy=True,
        )

    def verdict(self, packet: Packet, chain: str | None = None) -> str:
        return self.evaluate(packet, chain).verdict
