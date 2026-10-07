"""IPv4 packet model and a dependency-free header parser."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

PROTOCOL_NAMES = {1: "icmp", 6: "tcp", 17: "udp"}
PROTOCOL_NUMBERS = {name: number for number, name in PROTOCOL_NAMES.items()}

_IPv4_HEADER_MIN = 20


class PacketParseError(ValueError):
    """Raised when raw bytes cannot be parsed as an IPv4 packet."""


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
    if protocol in (PROTOCOL_NUMBERS["tcp"], PROTOCOL_NUMBERS["udp"]):
        if len(data) < offset + 4:
            raise PacketParseError("truncated transport header")
        sport = int.from_bytes(data[offset : offset + 2], "big")
        dport = int.from_bytes(data[offset + 2 : offset + 4], "big")
        return sport, dport
    return None, None


def parse_ipv4(data: bytes) -> Packet:
    """Parse a raw link-layer payload into a :class:`Packet`.

    Raises :class:`PacketParseError` for anything that is not a well-formed
    IPv4 packet; callers decide what verdict malformed traffic deserves.
    """
    if len(data) < _IPv4_HEADER_MIN:
        raise PacketParseError(f"packet too short: {len(data)} bytes")
    version = data[0] >> 4
    if version != 6 and version != 4:
        raise PacketParseError(f"unsupported IP version {version}")
    if version == 6:
        raise PacketParseError("IPv6 is out of scope")
    ihl = (data[0] & 0x0F) * 4
    if ihl < _IPv4_HEADER_MIN:
        raise PacketParseError(f"invalid IHL {ihl}")
    if len(data) < ihl:
        raise PacketParseError("truncated IPv4 header")

    total_len = int.from_bytes(data[2:4], "big")
    if total_len < ihl:
        raise PacketParseError(f"invalid total length {total_len}")

    fragment = int.from_bytes(data[6:8], "big")
    fragment_offset = fragment & 0x1FFF
    protocol_number = data[9]
    src = str(ipaddress.IPv4Address(data[12:16]))
    dst = str(ipaddress.IPv4Address(data[16:20]))

    sport = dport = None
    if fragment_offset == 0:
        sport, dport = _transport_ports(data, ihl, protocol_number)

    return Packet(
        src=src,
        dst=dst,
        protocol=protocol_name(protocol_number),
        sport=sport,
        dport=dport,
        raw_len=total_len,
    )
