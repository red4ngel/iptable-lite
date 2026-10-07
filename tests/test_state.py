import pytest

from iptable_lite.engine import Firewall
from iptable_lite.packet import Packet
from iptable_lite.rules import parse_config
from iptable_lite.state import (
    STATE_ESTABLISHED,
    STATE_NEW,
    FlowKey,
    StateTable,
)
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


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def table(clock):
    return StateTable(timeout=60, clock=clock)


class TestFlowKey:
    def test_is_direction_agnostic(self):
        forward = FlowKey.of(pkt())
        backward = FlowKey.of(reply(pkt()))
        assert forward == backward

    def test_different_ports_are_different_flows(self):
        assert FlowKey.of(pkt(dport=80)) != FlowKey.of(pkt(dport=81))

    def test_protocol_separates_flows(self):
        tcp = FlowKey.of(pkt(protocol="tcp"))
        udp = FlowKey.of(pkt(protocol="udp"))
        assert tcp != udp

    def test_icmp_ignores_missing_ports(self):
        echo = pkt(protocol="icmp", sport=None, dport=None)
        assert FlowKey.of(echo) == FlowKey.of(reply(echo))


class TestStateClassification:
    def test_first_packet_is_new(self, table):
        assert table.observe(pkt()) == STATE_NEW

    def test_second_packet_same_direction_is_established(self, table):
        table.observe(pkt())
        assert table.observe(pkt()) == STATE_ESTABLISHED

    def test_reverse_direction_is_established(self, table):
        first = pkt()
        table.observe(first)
        assert table.observe(reply(first)) == STATE_ESTABLISHED

    def test_distinct_flows_tracked_separately(self, table):
        table.observe(pkt(dport=80))
        assert table.observe(pkt(dport=443)) == STATE_NEW

    def test_state_of_lookup_without_creating(self, table):
        assert table.state_of(pkt()) is None
        table.observe(pkt())
        assert table.state_of(pkt()) == STATE_ESTABLISHED

    def test_len_tracks_entry_count(self, table):
        table.observe(pkt())
        table.observe(pkt(dport=443))
        assert len(table) == 2


class TestExpiry:
    def test_idle_entries_expire(self, table, clock):
        table.observe(pkt())
        clock.advance(59)
        assert table.expire() == 0
        clock.advance(2)
        assert table.expire() == 1
        assert len(table) == 0

    def test_expired_flow_starts_over_as_new(self, table, clock):
        table.observe(pkt())
        clock.advance(61)
        assert table.observe(pkt()) == STATE_NEW

    def test_activity_refreshes_the_entry(self, table, clock):
        table.observe(pkt())
        clock.advance(50)
        table.observe(pkt())  # refresh
        clock.advance(50)  # 50s since last seen, still under 60s timeout
        assert table.observe(pkt()) == STATE_ESTABLISHED

    def test_expire_returns_number_removed(self, table, clock):
        table.observe(pkt())
        table.observe(pkt(dport=443))
        clock.advance(61)
        assert table.expire() == 2

    def test_observe_expires_lazily(self, table, clock):
        table.observe(pkt())
        clock.advance(61)
        table.observe(pkt(dport=9999))  # triggers sweep
        assert len(table) == 1  # only the new flow remains

    @pytest.mark.parametrize("timeout", [0, -1])
    def test_invalid_timeout_rejected(self, timeout):
        with pytest.raises(ValueError):
            StateTable(timeout=timeout)


class TestAnnotate:
    def test_fills_state_when_missing(self, table):
        annotated = table.annotate(pkt())
        assert annotated.state == STATE_NEW

    def test_preserves_explicit_state(self, table):
        annotated = table.annotate(pkt(state="ESTABLISHED"))
        assert annotated.state == "ESTABLISHED"
        assert len(table) == 0  # nothing was observed

    def test_original_packet_untouched(self, table):
        original = pkt()
        table.annotate(original)
        assert original.state is None


class TestFirewallWithStateTable:
    def make_firewall(self, table):
        return Firewall(
            parse_config(
                "-P INPUT DROP\n"
                "-A INPUT -m state --state ESTABLISHED -j ACCEPT\n"
                "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
            ),
            state_table=table,
        )

    def test_new_connection_allowed_by_new_oriented_rule(self, table):
        fw = self.make_firewall(table)
        assert fw.verdict(pkt(dport=22)) == "ACCEPT"

    def test_reply_direction_allowed_by_state_rule(self, table):
        fw = self.make_firewall(table)
        first = pkt(dport=22)
        fw.verdict(first)
        assert fw.verdict(reply(first)) == "ACCEPT"

    def test_unrelated_new_connection_dropped(self, table):
        fw = self.make_firewall(table)
        assert fw.verdict(pkt(dport=3306)) == "DROP"

    def test_state_shown_in_verdict_log(self, table, caplog):
        fw = self.make_firewall(table)
        with caplog.at_level("INFO", logger=LOGGER_NAME):
            fw.verdict(pkt(dport=22))
        assert "state=NEW" in caplog.records[0].getMessage()

    def test_established_state_shown_in_log(self, table, caplog):
        fw = self.make_firewall(table)
        fw.verdict(pkt(dport=22))
        with caplog.at_level("INFO", logger=LOGGER_NAME):
            fw.verdict(pkt(dport=22))
        assert "state=ESTABLISHED" in caplog.records[0].getMessage()

    def test_expiry_reopens_the_flow(self, table, clock):
        fw = self.make_firewall(table)
        first = pkt(dport=22)
        assert fw.verdict(first) == "ACCEPT"  # NEW, matched ssh rule
        reply_packet = reply(first)
        assert fw.verdict(reply_packet) == "ACCEPT"  # ESTABLISHED
        clock.advance(61)
        assert fw.verdict(reply_packet) == "DROP"  # entry expired -> NEW again

    def test_state_rule_never_matches_without_table(self):
        fw = Firewall(
            parse_config(
                "-P INPUT DROP\n-A INPUT -m state --state ESTABLISHED -j ACCEPT\n"
            )
        )
        assert fw.verdict(pkt()) == "DROP"
