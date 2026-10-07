"""Helpers to craft raw IPv4 packets for tests."""

import ipaddress


def build_ipv4(
    src="10.0.0.1",
    dst="10.0.0.2",
    protocol=6,
    payload=b"",
    fragment_offset=0,
    ihl_words=5,
):
    header_len = ihl_words * 4
    header = bytearray(header_len)
    header[0] = (4 << 4) | ihl_words
    total = header_len + len(payload)
    header[2:4] = total.to_bytes(2, "big")
    header[6:8] = fragment_offset.to_bytes(2, "big")
    header[9] = protocol
    header[12:16] = ipaddress.IPv4Address(src).packed
    header[16:20] = ipaddress.IPv4Address(dst).packed
    return bytes(header) + payload


def tcp_payload(sport=12345, dport=80):
    return sport.to_bytes(2, "big") + dport.to_bytes(2, "big") + b"\x00" * 16


def udp_payload(sport=50000, dport=53):
    return sport.to_bytes(2, "big") + dport.to_bytes(2, "big") + b"\x00" * 8
