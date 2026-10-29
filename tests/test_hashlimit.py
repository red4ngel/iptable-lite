import logging

import pytest

from iptable_lite.engine import Firewall
from iptable_lite.events import ALERT_LOGGER_NAME, EVENT_LOGGER_NAME, EventEmitter
from iptable_lite.hashlimit import HashLimitTable
from iptable_lite.packet import Packet
from iptable_lite.rules import ParseError, parse_config, parse_rule
from iptable_lite.state import StateTable
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
        "dport": 22,
    }
    fields.update(overrides)
    return Packet(**fields)


def firewall(text, clock=None, throttle=0):
    clock = clock or FakeClock()
    events = EventEmitter(throttle=throttle, clock=clock)
    return Firewall(
        parse_config(text),
        state_table=StateTable(clock=clock),
        hashlimit_table=HashLimitTable(clock=clock),
        events=events,
    )


class TestHashlimitParsing:
    def test_defaults(self):
        rule = parse_rule(
            "-A INPUT -m hashlimit --hashlimit-name ssh "
            "--hashlimit-upto 5/minute -j ACCEPT"
        )
        spec = rule.match.hashlimit
        assert spec is not None
        assert spec.name == "ssh"
        assert spec.rate_per_second == pytest.approx(5 / 60)
        assert spec.above is False
        assert spec.burst == 5
        assert spec.mode == ("srcip",)
        assert spec.max_entries == 4096
        assert spec.expire_ms == 60000

    def test_all_options_and_above(self):
        rule = parse_rule(
            "-A INPUT -m hashlimit --hashlimit-name web --hashlimit-above 2/second "
            "--hashlimit-burst 7 --hashlimit-mode srcip,dstport "
            "--hashlimit-htable-max 12 --hashlimit-htable-expire 1500 -j DROP"
        )
        spec = rule.match.hashlimit
        assert spec.above is True
        assert spec.burst == 7
        assert spec.mode == ("srcip", "dstport")
        assert spec.max_entries == 12
        assert spec.expire_ms == 1500

    @pytest.mark.parametrize(
        "mode", ["srcip", "dstip", "dstport", "srcip,dstport", "srcip,dstip"]
    )
    def test_supported_modes(self, mode):
        rule = parse_rule(
            f"-A INPUT -m hashlimit --hashlimit-name n --hashlimit-upto 1/second "
            f"--hashlimit-mode {mode} -j ACCEPT"
        )
        assert ",".join(rule.match.hashlimit.mode) == mode

    @pytest.mark.parametrize(
        "line, message",
        [
            (
                "-A INPUT -m hashlimit --hashlimit-upto 1/second -j ACCEPT",
                "hashlimit-name",
            ),
            (
                "-A INPUT -m hashlimit --hashlimit-name n -j ACCEPT",
                "upto or --hashlimit-above",
            ),
            (
                "-A INPUT -m hashlimit --hashlimit-name n --hashlimit-upto 1/s "
                "--hashlimit-above 2/s -j ACCEPT",
                "duplicate",
            ),
            (
                "-A INPUT -m hashlimit --hashlimit-name n --hashlimit-upto 1/s "
                "--hashlimit-mode srcip,bogus -j ACCEPT",
                "unknown mode",
            ),
            (
                "-A INPUT -m hashlimit --hashlimit-name n --hashlimit-upto 1/s "
                "--hashlimit-mode srcip,srcip -j ACCEPT",
                "duplicate mode",
            ),
            (
                "-A INPUT -m hashlimit --hashlimit-name n --hashlimit-upto 1/s "
                "--hashlimit-htable-max 0 -j ACCEPT",
                "at least 1",
            ),
            (
                "-A INPUT -m hashlimit --hashlimit-name n --hashlimit-upto 1/s "
                "--hashlimit-htable-expire 0 -j ACCEPT",
                "at least 1",
            ),
            (
                "-A INPUT -m hashlimit ! --hashlimit-name n --hashlimit-upto 1/s "
                "-j ACCEPT",
                "cannot negate",
            ),
            (
                "-A INPUT ! -m hashlimit --hashlimit-name n --hashlimit-upto 1/s "
                "-j ACCEPT",
                "cannot negate",
            ),
        ],
    )
    def test_invalid_hashlimit_rules(self, line, message):
        with pytest.raises(ParseError, match=message):
            parse_rule(line)

    def test_reusing_name_with_different_mode_is_parse_error(self):
        with pytest.raises(ParseError, match="different mode or rate"):
            parse_config(
                "-A INPUT -m hashlimit --hashlimit-name n --hashlimit-upto 1/s -j ACCEPT\n"
                "-A OUTPUT -m hashlimit --hashlimit-name n --hashlimit-upto 1/s "
                "--hashlimit-mode dstip -j ACCEPT\n"
            )

    def test_reusing_name_with_different_rate_is_parse_error(self):
        with pytest.raises(ParseError, match="different mode or rate"):
            parse_config(
                "-A INPUT -m hashlimit --hashlimit-name n --hashlimit-upto 1/s -j ACCEPT\n"
                "-A OUTPUT -m hashlimit --hashlimit-name n --hashlimit-upto 2/s -j ACCEPT\n"
            )

    def test_reusing_name_with_same_mode_and_rate_is_allowed(self):
        ruleset = parse_config(
            "-A INPUT -m hashlimit --hashlimit-name n --hashlimit-upto 1/s -j ACCEPT\n"
            "-A OUTPUT -m hashlimit --hashlimit-name n --hashlimit-upto 1/s -j ACCEPT\n"
        )
        assert len(ruleset.rules) == 2


class TestHashlimitBehavior:
    RULES = (
        "-P INPUT DROP\n"
        "-A INPUT -p tcp --dport 22 -m hashlimit --hashlimit-name ssh "
        "--hashlimit-upto 5/minute --hashlimit-burst 5 -j ACCEPT\n"
    )

    def test_upto_allows_burst_then_denies(self):
        fw = firewall(self.RULES)
        results = [fw.verdict(pkt(sport=40000 + i)) for i in range(6)]
        assert results == ["ACCEPT"] * 5 + ["DROP"]

    def test_upto_refills(self):
        clock = FakeClock()
        fw = firewall(self.RULES, clock)
        for i in range(5):
            assert fw.verdict(pkt(sport=40000 + i)) == "ACCEPT"
        assert fw.verdict(pkt(sport=50000)) == "DROP"
        clock.advance(12)  # one token at 5/minute
        assert fw.verdict(pkt(sport=50001)) == "ACCEPT"

    def test_above_matches_only_when_exhausted(self):
        fw = firewall(
            "-P INPUT DROP\n"
            "-A INPUT -p tcp --dport 22 -m hashlimit --hashlimit-name ssh "
            "--hashlimit-above 5/minute --hashlimit-burst 5 -j DROP\n"
            "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
        )
        assert [fw.verdict(pkt(sport=40000 + i)) for i in range(5)] == [
            "ACCEPT"
        ] * 5
        assert fw.verdict(pkt(sport=50000)) == "DROP"

    def test_one_source_does_not_affect_another(self):
        fw = firewall(self.RULES)
        for i in range(5):
            assert fw.verdict(pkt(src="10.0.0.9", sport=40000 + i)) == "ACCEPT"
        assert fw.verdict(pkt(src="10.0.0.9", sport=50000)) == "DROP"
        assert fw.verdict(pkt(src="10.0.0.10", sport=50001)) == "ACCEPT"

    def test_dstip_mode_isolates_destinations(self):
        fw = firewall(
            "-P INPUT DROP\n"
            "-A INPUT -p tcp --dport 22 -m hashlimit --hashlimit-name ssh "
            "--hashlimit-upto 1/hour --hashlimit-burst 1 "
            "--hashlimit-mode dstip -j ACCEPT\n"
        )
        assert fw.verdict(pkt(dst="10.0.0.1")) == "ACCEPT"
        assert fw.verdict(pkt(dst="10.0.0.1")) == "DROP"
        assert fw.verdict(pkt(dst="10.0.0.2")) == "ACCEPT"

    def test_non_matching_packets_do_not_spend_tokens(self):
        fw = firewall(
            "-P INPUT DROP\n"
            "-A INPUT -p tcp --dport 22 -m hashlimit --hashlimit-name ssh "
            "--hashlimit-upto 1/hour --hashlimit-burst 1 -j ACCEPT\n"
        )
        for _ in range(10):
            assert fw.verdict(pkt(dport=80)) == "DROP"
        assert fw.verdict(pkt(dport=22)) == "ACCEPT"
        assert fw.verdict(pkt(dport=22)) == "DROP"

    def test_table_full_new_key_counts_as_over_and_alerts(self, caplog):
        clock = FakeClock()
        fw = firewall(
            "-P INPUT DROP\n"
            "-A INPUT -p tcp --dport 22 -m hashlimit --hashlimit-name ssh "
            "--hashlimit-upto 100/hour --hashlimit-burst 100 "
            "--hashlimit-htable-max 1 -j ACCEPT\n",
            clock,
        )
        with caplog.at_level(logging.WARNING, logger=EVENT_LOGGER_NAME):
            assert fw.verdict(pkt(src="10.0.0.1")) == "ACCEPT"
            assert fw.verdict(pkt(src="10.0.0.2")) == "DROP"
        assert any(
            "event=hashlimit_table_full severity=alert" in r.getMessage()
            for r in caplog.records
        )
        # The existing live key is still usable; no live entry was evicted.
        assert fw.hashlimit_table.bucket_count("ssh") == 1
        assert fw.verdict(pkt(src="10.0.0.1")) == "ACCEPT"

    def test_table_full_purges_idle_keys_first(self):
        clock = FakeClock()
        fw = firewall(
            "-P INPUT DROP\n"
            "-A INPUT -p tcp --dport 22 -m hashlimit --hashlimit-name ssh "
            "--hashlimit-upto 100/hour --hashlimit-burst 100 "
            "--hashlimit-htable-max 1 --hashlimit-htable-expire 1000 -j ACCEPT\n",
            clock,
        )
        assert fw.verdict(pkt(src="10.0.0.1")) == "ACCEPT"
        clock.advance(2)
        assert fw.verdict(pkt(src="10.0.0.2")) == "ACCEPT"
        assert fw.hashlimit_table.bucket_count("ssh") == 1

    def test_rate_limit_hit_event_is_warn(self, caplog):
        fw = firewall(
            "-P INPUT DROP\n"
            "-A INPUT -m hashlimit --hashlimit-name any --hashlimit-upto 1/hour "
            "--hashlimit-burst 1 -j ACCEPT\n"
        )
        with caplog.at_level(logging.WARNING, logger=EVENT_LOGGER_NAME):
            fw.verdict(pkt())
            fw.verdict(pkt())
        assert any(
            "event=rate_limit_hit severity=warn" in r.getMessage()
            for r in caplog.records
        )

    def test_hashlimit_table_full_alert_goes_to_alert_logger(self, caplog):
        clock = FakeClock()
        fw = firewall(
            "-P INPUT DROP\n"
            "-A INPUT -m hashlimit --hashlimit-name any --hashlimit-upto 1/hour "
            "--hashlimit-burst 1 --hashlimit-htable-max 1 -j ACCEPT\n",
            clock,
        )
        with caplog.at_level(logging.WARNING, logger=ALERT_LOGGER_NAME):
            fw.verdict(pkt(src="10.0.0.1"))
            fw.verdict(pkt(src="10.0.0.2"))
        assert any(
            "event=hashlimit_table_full" in r.getMessage()
            for r in caplog.records
        )
