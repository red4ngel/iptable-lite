import pytest

from iptable_lite.packet import Packet, PacketParseError, parse_ipv4
from packet_helpers import build_ipv4, tcp_payload


class TestParseIPv4:
    def test_tcp_packet(self):
        pkt = parse_ipv4(build_ipv4(payload=tcp_payload(sport=12345, dport=443)))
        assert pkt.src == "10.0.0.1"
        assert pkt.dst == "10.0.0.2"
        assert pkt.protocol == "tcp"
        assert pkt.sport == 12345
        assert pkt.dport == 443

    def test_udp_packet(self):
        payload = (53).to_bytes(2, "big") + (5353).to_bytes(2, "big")
        pkt = parse_ipv4(build_ipv4(protocol=17, payload=payload))
        assert pkt.protocol == "udp"
        assert pkt.sport == 53
        assert pkt.dport == 5353

    def test_icmp_packet_has_no_ports(self):
        pkt = parse_ipv4(build_ipv4(protocol=1, payload=b"\x08\x00" + b"\x00" * 6))
        assert pkt.protocol == "icmp"
        assert pkt.sport is None
        assert pkt.dport is None

    def test_unknown_protocol_kept_numeric(self):
        pkt = parse_ipv4(build_ipv4(protocol=47, payload=b"\x00" * 8))
        assert pkt.protocol == "47"

    def test_non_initial_fragment_hides_ports(self):
        pkt = parse_ipv4(
            build_ipv4(payload=tcp_payload(), fragment_offset=100),
        )
        assert pkt.sport is None
        assert pkt.dport is None

    def test_options_extend_header(self):
        pkt = parse_ipv4(build_ipv4(payload=tcp_payload(dport=22), ihl_words=6))
        assert pkt.dport == 22

    def test_five_tuple(self):
        pkt = parse_ipv4(build_ipv4(payload=tcp_payload(sport=1, dport=2)))
        assert pkt.five_tuple == "10.0.0.1:1 -> 10.0.0.2:2 proto=tcp"


class TestParseErrors:
    def test_empty(self):
        with pytest.raises(PacketParseError):
            parse_ipv4(b"")

    def test_truncated_header(self):
        with pytest.raises(PacketParseError):
            parse_ipv4(b"\x45" + b"\x00" * 10)

    def test_ipv6_rejected(self):
        with pytest.raises(PacketParseError, match="IPv6"):
            parse_ipv4(b"\x60" + b"\x00" * 39)

    def test_garbage_version(self):
        with pytest.raises(PacketParseError, match="version"):
            parse_ipv4(b"\x35" + b"\x00" * 19)

    def test_invalid_ihl(self):
        data = bytearray(build_ipv4())
        data[0] = 0x43  # IHL = 3 words < 20 bytes
        with pytest.raises(PacketParseError, match="IHL"):
            parse_ipv4(bytes(data))

    def test_truncated_after_ihl_claim(self):
        data = bytearray(build_ipv4(ihl_words=7))
        with pytest.raises(PacketParseError, match="truncated"):
            parse_ipv4(bytes(data[:24]))

    def test_truncated_tcp_header(self):
        with pytest.raises(PacketParseError, match="transport"):
            parse_ipv4(build_ipv4(payload=b"\x00\x50"))


def test_packet_is_hashable_and_immutable():
    pkt = parse_ipv4(build_ipv4(payload=tcp_payload()))
    assert {pkt} == {pkt}
