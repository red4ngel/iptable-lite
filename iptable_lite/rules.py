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

from iptable_lite.hashlimit import (
    DEFAULT_HASHLIMIT_BURST,
    DEFAULT_HASHLIMIT_EXPIRE_MS,
    DEFAULT_HASHLIMIT_MAX,
    DEFAULT_HASHLIMIT_MODE,
    VALID_HASHLIMIT_MODES,
    HashLimitSpec,
)
from iptable_lite.ratelimit import DEFAULT_BURST, DEFAULT_RATE

VALID_TARGETS = ("ACCEPT", "DROP")
VALID_STATES = frozenset({"NEW", "ESTABLISHED", "RELATED", "INVALID", "UNTRACKED"})
SUPPORTED_MODULES = frozenset(
    {"tcp", "udp", "icmp", "state", "conntrack", "comment", "limit", "hashlimit"}
)
IGNORED_OPTIONS = frozenset({"-v", "--verbose", "-n", "--numeric", "-x", "--exact", "--line-numbers"})

_SOURCE_OPTIONS = ("-s", "--src", "--source")
_DEST_OPTIONS = ("-d", "--dst", "--destination")
_PROTO_OPTIONS = ("-p", "--proto", "--protocol")
_SPORT_OPTIONS = ("--sport", "--source-port")
_DPORT_OPTIONS = ("--dport", "--destination-port")
_STATE_OPTIONS = ("--state", "--ctstate")
_JUMP_OPTIONS = ("-j", "--jump")

_RATE_UNITS = {
    "second": 1,
    "seconds": 1,
    "sec": 1,
    "secs": 1,
    "s": 1,
    "minute": 60,
    "minutes": 60,
    "min": 60,
    "mins": 60,
    "m": 60,
    "hour": 3600,
    "hours": 3600,
    "hr": 3600,
    "hrs": 3600,
    "h": 3600,
    "day": 86400,
    "days": 86400,
    "d": 86400,
}


class ParseError(ValueError):
    """Raised when a rule line cannot be interpreted faithfully."""


@dataclass(frozen=True)
class LimitSpec:
    """Token-bucket parameters from ``-m limit`` (``--limit``/``--limit-burst``)."""

    rate_per_second: float
    burst: int


@dataclass(frozen=True)
class MatchSpec:
    """Header fields a rule matches on; ``None`` means "match anything"."""

    src: str | None = None
    dst: str | None = None
    protocol: str | None = None
    sport: tuple[int, int] | None = None
    dport: tuple[int, int] | None = None
    states: frozenset[str] | None = None
    limit: LimitSpec | None = None
    hashlimit: HashLimitSpec | None = None
    negated: frozenset[str] = frozenset()

    def is_empty(self) -> bool:
        return (
            self.src is None
            and self.dst is None
            and self.protocol is None
            and self.sport is None
            and self.dport is None
            and self.states is None
            and self.limit is None
            and self.hashlimit is None
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
    fallback_policy: str = "ACCEPT"

    def default_policy(self, chain: str) -> str:
        return self.policies.get(chain, self.fallback_policy)


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


def _normalize_rate(value: str, option: str) -> float:
    amount, separator, unit = value.partition("/")
    if not separator:
        raise ParseError(f"{option}: rate must look like '5/minute', not {value!r}")
    try:
        count = int(amount)
    except ValueError as exc:
        raise ParseError(f"{option}: invalid rate {value!r}") from exc
    if count <= 0:
        raise ParseError(f"{option}: rate must be positive")
    seconds = _RATE_UNITS.get(unit.lower())
    if seconds is None:
        raise ParseError(f"{option}: unknown rate unit {unit!r}")
    return count / seconds


def _normalize_burst(value: str, option: str) -> int:
    try:
        burst = int(value)
    except ValueError as exc:
        raise ParseError(f"{option}: invalid burst {value!r}") from exc
    if burst < 1:
        raise ParseError(f"{option}: burst must be at least 1")
    return burst


def _normalize_hashlimit_mode(value: str) -> tuple[str, ...]:
    parts = tuple(part.strip().lower() for part in value.split(",") if part.strip())
    if not parts:
        raise ParseError("--hashlimit-mode requires at least one mode")
    unknown = set(parts) - VALID_HASHLIMIT_MODES
    if unknown:
        raise ParseError(
            f"--hashlimit-mode: unknown mode(s) {', '.join(sorted(unknown))}"
        )
    if len(set(parts)) != len(parts):
        raise ParseError("--hashlimit-mode contains a duplicate mode")
    return parts


def _normalize_positive_int(value: str, option: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise ParseError(f"{option}: invalid number {value!r}") from exc
    if number < 1:
        raise ParseError(f"{option}: must be at least 1")
    return number


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
    limit_module = False
    hashlimit_module = False
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
            if module == "limit":
                limit_module = True
            elif module == "hashlimit":
                hashlimit_module = True
            i += 2
            continue

        if token == "--limit":
            if negate_next:
                raise ParseError("'!' cannot negate a rate limit")
            if i + 1 >= len(tokens):
                raise ParseError("--limit requires a rate")
            claim("limit")
            fields["limit_rate"] = _normalize_rate(tokens[i + 1], token)
            i += 2
            continue

        if token == "--limit-burst":
            if negate_next:
                raise ParseError("'!' cannot negate a rate limit")
            if i + 1 >= len(tokens):
                raise ParseError("--limit-burst requires a count")
            claim("limit-burst")
            fields["limit_burst"] = _normalize_burst(tokens[i + 1], token)
            i += 2
            continue

        if token == "--hashlimit-name":
            if negate_next:
                raise ParseError("'!' cannot negate a hashlimit option")
            if i + 1 >= len(tokens):
                raise ParseError("--hashlimit-name requires a name")
            claim("hashlimit-name")
            name = tokens[i + 1]
            if not name or name.startswith("-"):
                raise ParseError("--hashlimit-name requires a non-empty name")
            fields["hashlimit_name"] = name
            i += 2
            continue

        if token in ("--hashlimit-upto", "--hashlimit-above"):
            if negate_next:
                raise ParseError("'!' cannot negate a hashlimit option")
            if i + 1 >= len(tokens):
                raise ParseError(f"{token} requires a rate")
            claim("hashlimit-rate")
            fields["hashlimit_rate"] = _normalize_rate(tokens[i + 1], token)
            fields["hashlimit_above"] = token == "--hashlimit-above"
            i += 2
            continue

        if token == "--hashlimit-burst":
            if negate_next:
                raise ParseError("'!' cannot negate a hashlimit option")
            if i + 1 >= len(tokens):
                raise ParseError("--hashlimit-burst requires a count")
            claim("hashlimit-burst")
            fields["hashlimit_burst"] = _normalize_positive_int(
                tokens[i + 1], token
            )
            i += 2
            continue

        if token == "--hashlimit-mode":
            if negate_next:
                raise ParseError("'!' cannot negate a hashlimit option")
            if i + 1 >= len(tokens):
                raise ParseError("--hashlimit-mode requires a mode")
            claim("hashlimit-mode")
            fields["hashlimit_mode"] = _normalize_hashlimit_mode(tokens[i + 1])
            i += 2
            continue

        if token == "--hashlimit-htable-max":
            if negate_next:
                raise ParseError("'!' cannot negate a hashlimit option")
            if i + 1 >= len(tokens):
                raise ParseError("--hashlimit-htable-max requires a number")
            claim("hashlimit-htable-max")
            fields["hashlimit_max"] = _normalize_positive_int(
                tokens[i + 1], token
            )
            i += 2
            continue

        if token == "--hashlimit-htable-expire":
            if negate_next:
                raise ParseError("'!' cannot negate a hashlimit option")
            if i + 1 >= len(tokens):
                raise ParseError("--hashlimit-htable-expire requires milliseconds")
            claim("hashlimit-htable-expire")
            fields["hashlimit_expire"] = _normalize_positive_int(
                tokens[i + 1], token
            )
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

    limit = None
    if limit_module or "limit_rate" in fields or "limit_burst" in fields:
        limit = LimitSpec(
            rate_per_second=fields.get("limit_rate", DEFAULT_RATE),  # type: ignore[arg-type]
            burst=fields.get("limit_burst", DEFAULT_BURST),  # type: ignore[arg-type]
        )

    hashlimit = None
    if hashlimit_module or any(
        key.startswith("hashlimit_") for key in fields
    ):
        name = fields.get("hashlimit_name")
        if not name:
            raise ParseError("-m hashlimit requires --hashlimit-name")
        if "hashlimit_rate" not in fields:
            raise ParseError(
                "-m hashlimit requires --hashlimit-upto or --hashlimit-above"
            )
        hashlimit = HashLimitSpec(
            name=str(name),
            rate_per_second=float(fields["hashlimit_rate"]),
            above=bool(fields.get("hashlimit_above", False)),
            burst=int(fields.get("hashlimit_burst", DEFAULT_HASHLIMIT_BURST)),
            mode=fields.get("hashlimit_mode", DEFAULT_HASHLIMIT_MODE),  # type: ignore[arg-type]
            max_entries=int(
                fields.get("hashlimit_max", DEFAULT_HASHLIMIT_MAX)
            ),
            expire_ms=int(
                fields.get("hashlimit_expire", DEFAULT_HASHLIMIT_EXPIRE_MS)
            ),
        )
    match = MatchSpec(
        src=fields.get("src"),  # type: ignore[arg-type]
        dst=fields.get("dst"),  # type: ignore[arg-type]
        protocol=fields.get("protocol"),  # type: ignore[arg-type]
        sport=fields.get("sport"),  # type: ignore[arg-type]
        dport=fields.get("dport"),  # type: ignore[arg-type]
        states=fields.get("states"),  # type: ignore[arg-type]
        limit=limit,
        hashlimit=hashlimit,
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
    hashlimits: dict[str, tuple[tuple[str, ...], float]] = {}
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
            rule = parse_rule(line, index=len(rules))
            spec = rule.match.hashlimit
            if spec is not None:
                signature = (spec.mode, spec.rate_per_second)
                previous = hashlimits.get(spec.name)
                if previous is not None and previous != signature:
                    raise fail(
                        f"hashlimit name {spec.name!r} reused with a different "
                        "mode or rate"
                    )
                hashlimits[spec.name] = signature
            rules.append(rule)
        except ParseError as exc:
            message = str(exc)
            if message.startswith(f"line {line_number}:"):
                raise
            raise fail(message) from exc

    return RuleSet(rules=tuple(rules), policies=policies)


def load_rules(path: str | Path) -> RuleSet:
    """Load filtering rules from a configuration source (FR-1)."""
    return parse_config(Path(path).read_text(encoding="utf-8"))
