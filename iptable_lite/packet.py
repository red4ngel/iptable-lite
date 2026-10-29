"""IPv4 packet model and a dependency-free header parser."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

PROTOCOL_NAMES = {1: "icmp", 6: "tcp", 17: "udp"}
PROTOCOL_NUMBERS = {name: number for number, name in PROTOCOL_NAMES.items()}

_IPv4_HEADER_MIN = 20
_TCP_HEADER_MIN = 20
_UDP_HEADER_MIN = 8
_ICMP_HEADER_MIN = 8


class PacketParseError(ValueError):
    """Raised when raw bytes cannot be parsed as an IPv4 packet."""


class FragmentError(PacketParseError):
    """Raised for an IPv4 fragment, which this filter always drops."""

    def __init__(self, message: str, src: str | None = None):
        super().__init__(message)
        self.src = src


@dataclass(frozen=True)
class Packet:
    """A flattened view of the header fields rules can match on."""

    src: str
    dst: str
    protocol: str
    sport: int | None = None
    dport: int | None = None
    state: str | None = None
    chain: str = "INPUT"
    raw_len: int = field(default=0, compare=False)

    @property
    def five_tuple(self) -> str:
        src_port = str(self.sport) if self.sport is not None else "*"
        dst_port = str(self.dport) if self.dport is not None else "*"
        return f"{self.src}:{src_port} -> {self.dst}:{dst_port} proto={self.protocol}"


def protocol_name(number: int) -> str:
    return PROTOCOL_NAMES.get(number, str(number))


def _transport_ports(data: bytes, offset: int, protocol: int) -> tuple[int | None, int | None]:
    payload_length = len(data) - offset
    minimum = {
        PROTOCOL_NUMBERS["tcp"]: _TCP_HEADER_MIN,
        PROTOCOL_NUMBERS["udp"]: _UDP_HEADER_MIN,
        PROTOCOL_NUMBERS["icmp"]: _ICMP_HEADER_MIN,
    }.get(protocol)
    if minimum is not None and payload_length < minimum:
        raise PacketParseError(
            f"truncated transport header: {payload_length} bytes"
        )
    if protocol in (PROTOCOL_NUMBERS["tcp"], PROTOCOL_NUMBERS["udp"]):
        sport = int.from_bytes(data[offset : offset + 2], "big")
        dport = int.from_bytes(data[offset + 2 : offset + 4], "big")
        return sport, dport
    return None, None


def parse_ipv4(data: bytes) -> Packet:
    """Parse a raw link-layer payload into a :class:`Packet`.

    Raises :class:`PacketParseError` for anything that is not a well-formed
    IPv4 packet; fragments raise :class:`FragmentError`.  Callers decide what
    verdict malformed or fragmented traffic deserves.
    """
    if len(data) < _IPv4_HEADER_MIN:
        raise PacketParseError(f"packet too short: {len(data)} bytes")
    version = data[0] >> 4
    if version != 4:
        if version == 6:
            raise PacketParseError("IPv6 is out of scope")
        raise PacketParseError(f"unsupported IP version {version}")
    ihl = (data[0] & 0x0F) * 4
    if ihl < _IPv4_HEADER_MIN:
        raise PacketParseError(f"invalid IHL {ihl}")
    if len(data) < ihl:
        raise PacketParseError("truncated IPv4 header")

    total_len = int.from_bytes(data[2:4], "big")
    if total_len < ihl:
        raise PacketParseError(f"invalid total length {total_len} (IHL {ihl})")
    if total_len > len(data):
        raise PacketParseError(
            f"truncated IPv4 packet: total length {total_len}, got {len(data)} bytes"
        )

    fragment = int.from_bytes(data[6:8], "big")
    fragment_offset = fragment & 0x1FFF
    more_fragments = bool(fragment & 0x2000)
    protocol_number = data[9]
    src = str(ipaddress.IPv4Address(data[12:16]))
    dst = str(ipaddress.IPv4Address(data[16:20]))

    if more_fragments or fragment_offset > 0:
        reason = "MF set" if more_fragments else f"offset {fragment_offset}"
        raise FragmentError(f"fragment ({reason})", src=src)

    # Only the bytes covered by total_len are part of the IP packet.  A
    # transport header entirely inside that boundary is required.
    payload = data[ihl:total_len]
    sport = dport = None
    sport, dport = _transport_ports(payload, 0, protocol_number)

    return Packet(
        src=src,
        dst=dst,
        protocol=protocol_name(protocol_number),
        sport=sport,
        dport=dport,
        raw_len=total_len,
    )
