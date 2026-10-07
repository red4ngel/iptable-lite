import logging

import pytest

from iptable_lite.engine import Firewall
from iptable_lite.packet import Packet
from iptable_lite.rules import parse_config
from iptable_lite.verdicts import LOGGER_NAME, configure, log_verdict


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


@pytest.fixture
def firewall():
    return Firewall(
        parse_config(
            "-P INPUT DROP\n"
            "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
            "-A INPUT -p tcp --dport 80 -j ACCEPT\n"
        )
    )


class TestVerdictLogging:
    def test_each_verdict_is_logged_exactly_once(self, firewall, caplog):
        with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
            firewall.verdict(pkt(dport=22))
        assert len(caplog.records) == 1

    def test_rule_match_verdict_content(self, firewall, caplog):
        with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
            firewall.verdict(pkt(dport=22))
        message = caplog.records[0].getMessage()
        assert "verdict=ACCEPT" in message
        assert "chain=INPUT" in message
        assert "10.0.0.9:40000 -> 10.0.0.1:22 proto=tcp" in message
        assert "rule[0]" in message
        assert "default policy" not in message

    def test_policy_verdict_is_logged(self, firewall, caplog):
        with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
            firewall.verdict(pkt(dport=3306))
        message = caplog.records[0].getMessage()
        assert "verdict=DROP" in message
        assert "reason=default policy" in message

    def test_drop_rule_verdict_is_logged(self, caplog):
        fw = Firewall(parse_config("-A INPUT -j DROP\n"))
        with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
            fw.verdict(pkt())
        assert "verdict=DROP" in caplog.records[0].getMessage()

    def test_every_packet_gets_its_own_log_line(self, firewall, caplog):
        with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
            firewall.verdict(pkt(dport=22))
            firewall.verdict(pkt(dport=80))
            firewall.verdict(pkt(dport=9999))
        assert len(caplog.records) == 3
        verdicts = [r.getMessage().split()[0] for r in caplog.records]
        assert verdicts == ["verdict=ACCEPT", "verdict=ACCEPT", "verdict=DROP"]

    def test_state_is_included_when_present(self, caplog):
        fw = Firewall(parse_config("-P INPUT DROP\n-A INPUT -m state --state NEW -j DROP\n"))
        with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
            fw.verdict(pkt(state="NEW"))
        assert "state=NEW" in caplog.records[0].getMessage()

    def test_missing_state_rendered_as_dash(self, caplog):
        fw = Firewall(parse_config("-A INPUT -j ACCEPT\n"))
        with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
            fw.verdict(pkt())
        assert "state=-" in caplog.records[0].getMessage()

    def test_chain_is_logged(self, caplog):
        fw = Firewall(parse_config("-A OUTPUT -j ACCEPT\n"))
        with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
            fw.verdict(pkt(chain="OUTPUT"))
        message = caplog.records[0].getMessage()
        assert "chain=OUTPUT" in message
        assert "verdict=ACCEPT" in message


class TestConfigure:
    def test_configure_adds_single_handler(self):
        target = configure()
        try:
            assert len(target.handlers) == 1
            configure()  # idempotent
            assert len(target.handlers) == 1
        finally:
            target.handlers.clear()
            target.setLevel(logging.NOTSET)
            target.propagate = True

    def test_log_verdict_directly(self, caplog):
        from iptable_lite.engine import Evaluation

        with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
            log_verdict(Evaluation(verdict="DROP", used_default_policy=True), pkt(), "INPUT")
        assert "verdict=DROP" in caplog.records[0].getMessage()
