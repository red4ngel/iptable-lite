import logging

import pytest

from iptable_lite import nfqueue_source
from iptable_lite.engine import Firewall
from iptable_lite.rules import parse_config
from iptable_lite.verdicts import LOGGER_NAME
from packet_helpers import build_ipv4, tcp_payload


class FakeNfPacket:
    def __init__(self, payload: bytes):
        self.payload = payload
        self.action = None

    def get_payload(self):
        return self.payload

    def accept(self):
        self.action = "accept"

    def drop(self):
        self.action = "drop"


def firewall(text):
    return Firewall(parse_config(text))


ACCEPTING = firewall("-A INPUT -p tcp --dport 22 -j ACCEPT\n-P INPUT DROP\n")


class TestCallback:
    def test_packet_matching_accept_rule_is_accepted(self):
        fake = FakeNfPacket(build_ipv4(payload=tcp_payload(dport=22)))
        nfqueue_source.make_callback(ACCEPTING)(fake)
        assert fake.action == "accept"

    def test_packet_matching_drop_rule_is_dropped(self):
        fw = firewall("-A INPUT -j DROP\n")
        fake = FakeNfPacket(build_ipv4(payload=tcp_payload(dport=80)))
        nfqueue_source.make_callback(fw)(fake)
        assert fake.action == "drop"

    def test_packet_with_no_matching_rule_gets_policy_verdict(self):
        fake = FakeNfPacket(build_ipv4(payload=tcp_payload(dport=8080)))
        nfqueue_source.make_callback(ACCEPTING)(fake)
        assert fake.action == "drop"

    def test_malformed_packet_is_dropped_and_logged(self, caplog):
        fake = FakeNfPacket(b"\x00\x01\x02")
        with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
            nfqueue_source.make_callback(ACCEPTING)(fake)
        assert fake.action == "drop"
        message = caplog.records[0].getMessage()
        assert "verdict=DROP" in message
        assert "reason=malformed packet" in message

    def test_ipv6_packet_is_dropped(self):
        fake = FakeNfPacket(b"\x60" + b"\x00" * 39)
        nfqueue_source.make_callback(ACCEPTING)(fake)
        assert fake.action == "drop"

    def test_chain_can_be_overridden(self, caplog):
        fw = firewall("-A FORWARD -j DROP\n-A INPUT -j ACCEPT\n")
        callback = nfqueue_source.make_callback(fw, chain="FORWARD")
        fake = FakeNfPacket(build_ipv4(payload=tcp_payload()))
        with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
            callback(fake)
        assert fake.action == "drop"
        assert "chain=FORWARD" in caplog.records[0].getMessage()

    def test_verdict_is_logged_for_every_nfqueue_packet(self, caplog):
        with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
            for dport in (22, 8080):
                fake = FakeNfPacket(build_ipv4(payload=tcp_payload(dport=dport)))
                nfqueue_source.make_callback(ACCEPTING)(fake)
        assert len(caplog.records) == 2


class TestRunQueue:
    def test_missing_library_raises_helpful_error(self, monkeypatch):
        def boom():
            raise ImportError("no netfilterqueue here")

        monkeypatch.setattr(nfqueue_source, "_load_netfilterqueue", boom)
        with pytest.raises(RuntimeError, match="NetfilterQueue is required"):
            nfqueue_source.run_queue(0, ACCEPTING)

    def test_binds_runs_and_unbinds(self, monkeypatch):
        created = {}

        class FakeQueue:
            def bind(self, queue_num, callback):
                created["queue_num"] = queue_num
                created["callback"] = callback

            def run(self):
                created["ran"] = True

            def unbind(self):
                created["unbound"] = True

        monkeypatch.setattr(nfqueue_source, "_load_netfilterqueue", lambda: FakeQueue)
        nfqueue_source.run_queue(3, ACCEPTING, chain="FORWARD")
        assert created == {
            "queue_num": 3,
            "callback": created["callback"],
            "ran": True,
            "unbound": True,
        }
        assert callable(created["callback"])

    def test_unbinds_when_interrupted(self, monkeypatch):
        state = {"unbound": False}

        class FakeQueue:
            def bind(self, queue_num, callback):
                pass

            def run(self):
                raise KeyboardInterrupt

            def unbind(self):
                state["unbound"] = True

        monkeypatch.setattr(nfqueue_source, "_load_netfilterqueue", lambda: FakeQueue)
        nfqueue_source.run_queue(0, ACCEPTING)
        assert state["unbound"] is True
