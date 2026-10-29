import pytest

from iptable_lite.packet import FragmentError, PacketParseError, parse_ipv4
from packet_helpers import build_ipv4, icmp_payload, tcp_payload, udp_payload


def with_total_length(data, total):
    data = bytearray(data)
    data[2:4] = total.to_bytes(2, "big")
    return bytes(data)


class TestStrictHeaders:
    def test_total_length_larger_than_capture_is_truncated(self):
        data = with_total_length(build_ipv4(payload=tcp_payload()), 1000)
        with pytest.raises(PacketParseError, match="truncated"):
            parse_ipv4(data)

    def test_total_length_smaller_than_header_is_inconsistent(self):
        data = with_total_length(build_ipv4(payload=tcp_payload()), 10)
        with pytest.raises(PacketParseError, match="total length"):
            parse_ipv4(data)

    def test_total_length_shorter_than_transport_header(self):
        data = build_ipv4(payload=tcp_payload())
        data = with_total_length(data, 20 + 10)
        with pytest.raises(PacketParseError, match="transport"):
            parse_ipv4(data)

    def test_ipv6_is_rejected(self):
        with pytest.raises(PacketParseError, match="IPv6"):
            parse_ipv4(b"\x60" + b"\x00" * 39)

    @pytest.mark.parametrize("version", [0, 2, 5, 15])
    def test_wrong_version_is_rejected(self, version):
        data = bytearray(build_ipv4(payload=tcp_payload()))
        data[0] = (version << 4) | 5
        with pytest.raises(PacketParseError, match="version"):
            parse_ipv4(bytes(data))

    @pytest.mark.parametrize(
        "payload",
        [b"", b"\x00", b"\x00" * 7],
    )
    def test_truncated_udp_header_is_rejected(self, payload):
        with pytest.raises(PacketParseError, match="transport"):
            parse_ipv4(build_ipv4(protocol=17, payload=payload))

    @pytest.mark.parametrize("length", [0, 1, 4, 19])
    def test_truncated_tcp_header_is_rejected(self, length):
        with pytest.raises(PacketParseError, match="transport"):
            parse_ipv4(build_ipv4(payload=b"\x00" * length))

    @pytest.mark.parametrize("length", [0, 1, 7])
    def test_truncated_icmp_header_is_rejected(self, length):
        with pytest.raises(PacketParseError, match="transport"):
            parse_ipv4(build_ipv4(protocol=1, payload=b"\x00" * length))

    def test_minimum_headers_parse(self):
        assert parse_ipv4(build_ipv4(payload=tcp_payload())).protocol == "tcp"
        assert (
            parse_ipv4(build_ipv4(protocol=17, payload=udp_payload())).protocol
            == "udp"
        )
        assert (
            parse_ipv4(build_ipv4(protocol=1, payload=icmp_payload())).protocol
            == "icmp"
        )


class TestFragments:
    def test_mf_flag_is_rejected(self):
        with pytest.raises(FragmentError, match="MF"):
            parse_ipv4(build_ipv4(payload=tcp_payload(), mf=True))

    @pytest.mark.parametrize("offset", [1, 100, 8191])
    def test_nonzero_offset_is_rejected(self, offset):
        with pytest.raises(FragmentError, match="offset"):
            parse_ipv4(
                build_ipv4(payload=tcp_payload(), fragment_offset=offset)
            )

    def test_fragment_carries_source_for_events(self):
        with pytest.raises(FragmentError) as excinfo:
            parse_ipv4(
                build_ipv4(
                    src="198.51.100.7",
                    payload=tcp_payload(),
                    fragment_offset=10,
                )
            )
        assert excinfo.value.src == "198.51.100.7"


class TestUnknownProtocol:
    def test_unknown_protocol_is_kept_numeric(self):
        packet = parse_ipv4(build_ipv4(protocol=47, payload=b"\x01\x02\x03"))
        assert packet.protocol == "47"
        assert packet.sport is None
        assert packet.dport is None
