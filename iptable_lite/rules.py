"""Parsing of plain-text iptables-style rule files (FR-1, FR-4).

Supported syntax mirrors what `iptables-save` prints for the filter table
plus plain command lines such as::

    iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 80 -j ACCEPT

Anything the filter cannot honourably enforce (interfaces, fragments,
user-defined chains, non-ACCEPT/DROP targets) raises :class:`ParseError`
instead of being silently ignored.
"""

from __future__ import annotations

import ipaddress
import shlex
from dataclasses import dataclass, field
from pathlib import Path

VALID_TARGETS = ("ACCEPT", "DROP")
VALID_STATES = frozenset({"NEW", "ESTABLISHED", "RELATED", "INVALID", "UNTRACKED"})
SUPPORTED_MODULES = frozenset({"tcp", "udp", "icmp", "state", "conntrack", "comment"})
IGNORED_OPTIONS = frozenset({"-v", "--verbose", "-n", "--numeric", "-x", "--exact", "--line-numbers"})

_SOURCE_OPTIONS = ("-s", "--src", "--source")
_DEST_OPTIONS = ("-d", "--dst", "--destination")
_PROTO_OPTIONS = ("-p", "--proto", "--protocol")
_SPORT_OPTIONS = ("--sport", "--source-port")
_DPORT_OPTIONS = ("--dport", "--destination-port")
_STATE_OPTIONS = ("--state", "--ctstate")
_JUMP_OPTIONS = ("-j", "--jump")


class ParseError(ValueError):
    """Raised when a rule line cannot be interpreted faithfully."""


@dataclass(frozen=True)
class MatchSpec:
    """Header fields a rule matches on; ``None`` means "match anything"."""

    src: str | None = None
    dst: str | None = None
    protocol: str | None = None
    sport: tuple[int, int] | None = None
    dport: tuple[int, int] | None = None
    states: frozenset[str] | None = None
    negated: frozenset[str] = frozenset()

    def is_empty(self) -> bool:
        return (
            self.src is None
            and self.dst is None
            and self.protocol is None
            and self.sport is None
            and self.dport is None
            and self.states is None
            and not self.negated
        )


@dataclass(frozen=True)
class Rule:
    chain: str
    match: MatchSpec
    target: str
    raw: str
    index: int = 0


@dataclass(frozen=True)
class RuleSet:
    """Ordered rules plus the default policy per chain (FR-5)."""

    rules: tuple[Rule, ...] = ()
    policies: dict[str, str] = field(default_factory=dict)

    def default_policy(self, chain: str) -> str:
        return self.policies.get(chain, "ACCEPT")


def _normalize_network(value: str, option: str) -> str:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ParseError(f"{option}: invalid address {value!r}") from exc
    if network.version != 4:
        raise ParseError(f"{option}: IPv6 is out of scope")
    return str(network)


def _normalize_protocol(value: str) -> str | None:
    proto = value.lower()
    if proto == "all":
        return None
    if proto.isdigit():
        numeric = int(proto)
        if numeric in (1, 6, 17):
            return {1: "icmp", 6: "tcp", 17: "udp"}[numeric]
        return str(numeric)
    if proto in ("tcp", "udp", "icmp"):
        return proto
    raise ParseError(f"unsupported protocol {value!r}")


def _normalize_port(value: str, option: str) -> tuple[int, int]:
    if ":" in value:
        start, _, end = value.partition(":")
        try:
            low, high = int(start), int(end)
        except ValueError as exc:
            raise ParseError(f"{option}: invalid port range {value!r}") from exc
    else:
        try:
            low = high = int(value)
        except ValueError as exc:
            raise ParseError(f"{option}: invalid port {value!r}") from exc
    if not (0 <= low <= high <= 65535):
        raise ParseError(f"{option}: port out of range in {value!r}")
    return low, high


def _normalize_states(value: str) -> frozenset[str]:
    states = frozenset(part.strip().upper() for part in value.split(",") if part.strip())
    unknown = states - VALID_STATES
    if unknown:
        raise ParseError(f"unknown connection state(s): {', '.join(sorted(unknown))}")
    if not states:
        raise ParseError("empty connection state list")
    return states


def _strip_command_prefix(tokens: list[str]) -> list[str]:
    if tokens and tokens[0] in ("iptables", "ip6tables"):
        if tokens[0] == "ip6tables":
            raise ParseError("IPv6 is out of scope")
        tokens = tokens[1:]
    if tokens and tokens[0] in ("-4", "-6"):
        if tokens[0] == "-6":
            raise ParseError("IPv6 is out of scope")
        tokens = tokens[1:]
    while tokens and tokens[0] in ("-w", "--wait", "-t", "--table"):
        option = tokens[0]
        if len(tokens) < 2:
            raise ParseError(f"{option} requires a value")
        value = tokens[1]
        if option in ("-t", "--table") and value != "filter":
            raise ParseError(f"only the filter table is supported, not {value!r}")
        tokens = tokens[2:]
    return tokens


def parse_rule(line: str, index: int = 0) -> Rule:
    """Parse a single rule line into a :class:`Rule`."""
    raw = line.strip()
    if not raw:
        raise ParseError("empty rule line")
    try:
        tokens = shlex.split(raw, comments=False)
    except ValueError as exc:
        raise ParseError(f"cannot tokenize rule: {exc}") from exc
    if not tokens:
        raise ParseError("empty rule line")
    tokens = _strip_command_prefix(tokens)

    chain = "INPUT"
    target: str | None = None
    seen: set[str] = set()
    negate_next = False
    fields: dict[str, object] = {}
    negated: set[str] = set()

    def claim(kind: str) -> None:
        if kind in seen:
            raise ParseError(f"duplicate {kind} match in rule")
        seen.add(kind)

    i = 0
    while i < len(tokens):
        token = tokens[i]

        if token == "!":
            if negate_next:
                raise ParseError("repeated '!' negation")
            negate_next = True
            i += 1
            continue

        if token in ("-A", "--append", "-I", "--insert"):
            if i + 1 >= len(tokens):
                raise ParseError(f"{token} requires a chain name")
            chain = tokens[i + 1]
            i += 2
            if token in ("-I", "--insert") and i < len(tokens) and tokens[i].isdigit():
                i += 1  # rule number after -I
            continue

        if token in ("-P", "--policy"):
            raise ParseError("policy lines are not rules; use load_rules()")

        if token in _SOURCE_OPTIONS or token in _DEST_OPTIONS:
            kind = "src" if token in _SOURCE_OPTIONS else "dst"
            if i + 1 >= len(tokens):
                raise ParseError(f"{token} requires an address")
            claim(kind)
            value = _normalize_network(tokens[i + 1], token)
            if negate_next:
                negated.add(kind)
            fields[kind] = value
            negate_next = False
            i += 2
            continue

        if token in _PROTO_OPTIONS:
            if i + 1 >= len(tokens):
                raise ParseError(f"{token} requires a protocol")
            claim("protocol")
            value = _normalize_protocol(tokens[i + 1])
            if negate_next:
                negated.add("protocol")
                negate_next = False
            if value is not None:
                fields["protocol"] = value
            elif "protocol" in negated:
                negated.discard("protocol")  # '! -p all' matches nothing useful; treat as unconstrained
            i += 2
            continue

        if token in _SPORT_OPTIONS or token in _DPORT_OPTIONS:
            kind = "sport" if token in _SPORT_OPTIONS else "dport"
            if i + 1 >= len(tokens):
                raise ParseError(f"{token} requires a port")
            claim(kind)
            value = _normalize_port(tokens[i + 1], token)
            if negate_next:
                negated.add(kind)
            fields[kind] = value
            negate_next = False
            i += 2
            continue

        if token in _STATE_OPTIONS:
            if i + 1 >= len(tokens):
                raise ParseError(f"{token} requires a state list")
            claim("states")
            value = _normalize_states(tokens[i + 1])
            if negate_next:
                negated.add("states")
            fields["states"] = value
            negate_next = False
            i += 2
            continue

        if token in ("-m", "--match"):
            if negate_next:
                raise ParseError("'!' cannot negate a match module")
            if i + 1 >= len(tokens):
                raise ParseError(f"{token} requires a module name")
            module = tokens[i + 1].lower()
            if module not in SUPPORTED_MODULES:
                raise ParseError(f"unsupported match module {module!r}")
            i += 2
            continue

        if token == "--comment":
            if i + 1 >= len(tokens):
                raise ParseError("--comment requires a value")
            i += 2
            continue

        if token == "-c":  # iptables-save packet/byte counters
            if i + 2 >= len(tokens):
                raise ParseError("-c requires two counters")
            i += 3
            continue

        if token in _JUMP_OPTIONS:
            if i + 1 >= len(tokens):
                raise ParseError(f"{token} requires a target")
            target = tokens[i + 1].upper()
            if target not in VALID_TARGETS:
                raise ParseError(
                    f"unsupported target {target!r}; only ACCEPT and DROP are enforced"
                )
            if negate_next:
                raise ParseError("'!' cannot negate a jump target")
            i += 2
            continue

        if token in IGNORED_OPTIONS:
            i += 1
            continue

        if token in ("-i", "--in-interface", "-o", "--out-interface"):
            raise ParseError(f"interface matching is not supported ({token})")
        if token in ("-f", "--fragment"):
            raise ParseError("fragment matching is not supported")
        if token in ("-g", "--goto"):
            raise ParseError("user-defined chains are not supported")

        raise ParseError(f"unsupported option {token!r}")

    if negate_next:
        raise ParseError("dangling '!' negation at end of rule")
    if target is None:
        raise ParseError(f"rule has no jump target: {raw!r}")

    match = MatchSpec(
        src=fields.get("src"),  # type: ignore[arg-type]
        dst=fields.get("dst"),  # type: ignore[arg-type]
        protocol=fields.get("protocol"),  # type: ignore[arg-type]
        sport=fields.get("sport"),  # type: ignore[arg-type]
        dport=fields.get("dport"),  # type: ignore[arg-type]
        states=fields.get("states"),  # type: ignore[arg-type]
        negated=frozenset(negated),
    )
    return Rule(chain=chain, match=match, target=target, raw=raw, index=index)


def _parse_policy(token_target: str, raw: str) -> tuple[str, str]:
    chain, _, policy = token_target.partition(" ")
    policy = policy.split()[0] if policy else ""
    policy = policy.upper()
    if not chain or policy not in VALID_TARGETS:
        raise ParseError(f"invalid policy line: {raw!r}")
    return chain, policy


def parse_config(text: str) -> RuleSet:
    """Parse a whole rule file (plain commands or `iptables-save` output)."""
    rules: list[Rule] = []
    policies: dict[str, str] = {}
    table = "filter"

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        def fail(message: str) -> ParseError:
            return ParseError(f"line {line_number}: {message}")

        try:
            if line.startswith("*"):
                table = line[1:].strip()
                continue
            if line.upper() == "COMMIT":
                table = "filter"
                continue
            if line.startswith(":"):
                # ':INPUT DROP [0:0]' chain declaration from iptables-save
                if table != "filter":
                    continue
                body = line[1:].strip()
                parts = body.split()
                if len(parts) >= 2:
                    policy = parts[1].upper()
                    if policy in VALID_TARGETS:
                        policies[parts[0]] = policy
                continue
            if line.startswith("-P") or line.startswith("--policy"):
                tokens = shlex.split(line)
                chain = tokens[1] if len(tokens) > 1 else ""
                policy = tokens[2].upper() if len(tokens) > 2 else ""
                if policy not in VALID_TARGETS:
                    raise fail(f"invalid policy {policy!r}")
                policies[chain] = policy
                continue
            if table != "filter":
                continue  # we only filter; other tables are out of scope
            rules.append(parse_rule(line, index=len(rules)))
        except ParseError as exc:
            message = str(exc)
            if message.startswith(f"line {line_number}:"):
                raise
            raise fail(message) from exc

    return RuleSet(rules=tuple(rules), policies=policies)


def load_rules(path: str | Path) -> RuleSet:
    """Load filtering rules from a configuration source (FR-1)."""
    return parse_config(Path(path).read_text(encoding="utf-8"))
