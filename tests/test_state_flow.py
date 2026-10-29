import logging

import pytest

from iptable_lite.engine import Firewall
from iptable_lite.events import EVENT_LOGGER_NAME, EventEmitter
from iptable_lite.packet import Packet
from iptable_lite.rules import parse_config
from iptable_lite.state import FlowKey, StateTable
from iptable_lite.verdicts import LOGGER_NAME


class FakeClock:
    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def pkt(**overrides):
    fields = {
        "src": "10.0.0.9",
        "dst": "10.0.0.1",
        "protocol": "tcp",
        "sport": 40000,
        "dport": 80,
    }
    fields.update(overrides)
    return Packet(**fields)


def reply(packet):
    return Packet(
        src=packet.dst,
        dst=packet.src,
        protocol=packet.protocol,
        sport=packet.dport,
        dport=packet.sport,
    )


def build_firewall(text, clock, max_entries=65536, throttle=0):
    table = StateTable(timeout=60, clock=clock, max_entries=max_entries)
    events = EventEmitter(throttle=throttle, clock=clock)
    firewall = Firewall(
        parse_config(text), state_table=table, events=events
    )
    return firewall, table, events


class TestStateOnlyAfterAccept:
    def test_dropped_smb_syn_and_retry_stay_new(self, caplog):
        clock = FakeClock()
        fw, table, _ = build_firewall(
            "-P INPUT DROP\n"
            "-A INPUT -m state --state ESTABLISHED -j ACCEPT\n"
            "-A INPUT -p tcp --dport 445 -j DROP\n",
            clock,
        )
        smb = pkt(dport=445)
        with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
            assert fw.verdict(smb) == "DROP"
            assert fw.verdict(smb) == "DROP"
        assert len(table) == 0
        assert table.state_of(smb) is None
        assert caplog.records[0].getMessage().count("state=NEW") == 1
        assert caplog.records[1].getMessage().count("state=NEW") == 1

    def test_accepted_flow_creates_state_and_reply_is_established(self, clock=None):
        clock = FakeClock()
        fw, table, _ = build_firewall(
            "-P INPUT DROP\n"
            "-A INPUT -m state --state ESTABLISHED -j ACCEPT\n"
            "-A INPUT -p tcp --dport 80 -j ACCEPT\n",
            clock,
        )
        forward = pkt(dport=80)
        assert fw.verdict(forward) == "ACCEPT"
        assert table.state_of(forward) == "ESTABLISHED"
        assert fw.verdict(reply(forward)) == "ACCEPT"

    def test_dropped_established_packet_does_not_refresh_state(self):
        clock = FakeClock()
        fw, table, _ = build_firewall(
            "-P INPUT DROP\n"
            "-A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT\n"
            "-A INPUT -p tcp --dport 22 -j DROP\n",
            clock,
        )
        flow = pkt(dport=22)
        assert fw.verdict(flow) == "ACCEPT"
        key = FlowKey.of(flow)
        original_last_seen = table._entries[key].last_seen
        clock.advance(10)
        assert fw.verdict(flow) == "DROP"  # ESTABLISHED, but explicitly dropped
        assert table._entries[key].last_seen == original_last_seen


class TestBoundedState:
    RULES = "-A INPUT -j ACCEPT\n"

    def test_full_table_keeps_live_entries_and_raises_alert(self, caplog):
        clock = FakeClock()
        fw, table, _ = build_firewall(
            self.RULES, clock, max_entries=2, throttle=0
        )
        first, second, third = (
            pkt(dport=80),
            pkt(dport=443),
            pkt(dport=8080),
        )
        with caplog.at_level(logging.WARNING, logger=EVENT_LOGGER_NAME):
            assert fw.verdict(first) == "ACCEPT"
            assert fw.verdict(second) == "ACCEPT"
            assert fw.verdict(third) == "ACCEPT"
        assert len(table) == 2
        assert table.state_of(first) == "ESTABLISHED"
        assert table.state_of(second) == "ESTABLISHED"
        assert table.state_of(third) is None
        assert any(
            "event=state_table_full severity=alert" in r.getMessage()
            for r in caplog.records
        )

    def test_new_flow_is_still_new_after_full_table(self):
        clock = FakeClock()
        fw, table, _ = build_firewall(
            self.RULES, clock, max_entries=1, throttle=0
        )
        assert fw.verdict(pkt(dport=80)) == "ACCEPT"
        other = pkt(dport=443)
        assert fw.verdict(other) == "ACCEPT"
        assert fw.evaluate(other).verdict == "ACCEPT"
        assert table.state_of(other) is None

    def test_expired_entries_are_purged_before_refusing(self, caplog):
        clock = FakeClock()
        fw, table, _ = build_firewall(
            self.RULES, clock, max_entries=1, throttle=0
        )
        first = pkt(dport=80)
        assert fw.verdict(first) == "ACCEPT"
        clock.advance(61)
        second = pkt(dport=443)
        with caplog.at_level(logging.WARNING, logger=EVENT_LOGGER_NAME):
            assert fw.verdict(second) == "ACCEPT"
        assert table.state_of(first) is None
        assert table.state_of(second) == "ESTABLISHED"
        assert not any(
            "state_table_full" in r.getMessage() for r in caplog.records
        )

    @pytest.mark.parametrize("max_entries", [0, -1])
    def test_invalid_limit_rejected(self, max_entries):
        with pytest.raises(ValueError, match="max_entries"):
            StateTable(max_entries=max_entries)
