import pytest

from iptable_lite.engine import ACCEPT, DROP, Firewall, rule_matches
from iptable_lite.packet import Packet
from iptable_lite.rules import parse_config


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


def firewall(text):
    return Firewall(parse_config(text))


class TestFirstMatchOrdering:
    def test_first_matching_rule_wins(self):
        fw = firewall(
            "-A INPUT -p tcp --dport 80 -j ACCEPT\n"
            "-A INPUT -p tcp -j DROP\n"
        )
        assert fw.verdict(pkt(dport=80)) == ACCEPT
        assert fw.verdict(pkt(dport=443)) == DROP

    def test_earlier_broad_rule_shadows_later_rule(self):
        fw = firewall("-A INPUT -j ACCEPT\n-A INPUT -j DROP\n")
        assert fw.verdict(pkt()) == ACCEPT

    def test_later_rule_reached_when_earlier_does_not_match(self):
        fw = firewall(
            "-A INPUT -s 192.168.0.0/16 -j ACCEPT\n"
            "-A INPUT -s 10.0.0.0/8 -j DROP\n"
        )
        assert fw.verdict(pkt(src="10.1.2.3")) == DROP
        assert fw.verdict(pkt(src="192.168.1.1")) == ACCEPT


class TestDefaultPolicy:
    def test_accept_policy_when_nothing_matches(self):
        fw = firewall("-A INPUT -s 192.168.0.0/16 -j DROP\n")
        eval_result = fw.evaluate(pkt())
        assert eval_result.verdict == ACCEPT
        assert eval_result.used_default_policy
        assert eval_result.rule is None

    def test_drop_policy_from_config(self):
        fw = firewall("-P INPUT DROP\n-A INPUT -p tcp --dport 22 -j ACCEPT\n")
        assert fw.verdict(pkt(dport=22)) == ACCEPT
        assert fw.verdict(pkt(dport=8080)) == DROP

    def test_policy_applies_per_chain(self):
        fw = firewall("-P INPUT DROP\n-P OUTPUT ACCEPT\n-A INPUT -j ACCEPT\n")
        assert fw.verdict(pkt(chain="INPUT")) == ACCEPT
        assert fw.verdict(pkt(protocol="icmp", chain="INPUT")) == ACCEPT
        fw = firewall("-P INPUT DROP\n-P OUTPUT ACCEPT\n")
        assert fw.verdict(pkt(chain="INPUT")) == DROP
        assert fw.verdict(pkt(chain="OUTPUT")) == ACCEPT

    def test_evaluate_reason_mentions_rule(self):
        fw = firewall("-A INPUT -p tcp --dport 22 -j ACCEPT\n")
        evaluation = fw.evaluate(pkt(dport=22))
        assert "rule[0]" in evaluation.reason
        assert evaluation.rule is not None
        assert evaluation.rule.index == 0


class TestHeaderFieldMatching:
    def test_source_cidr(self):
        fw = firewall("-A INPUT -s 10.0.0.0/8 -j DROP\n")
        assert fw.verdict(pkt(src="10.255.255.255")) == DROP
        assert fw.verdict(pkt(src="11.0.0.1")) == ACCEPT  # default policy

    def test_destination_address(self):
        fw = firewall("-A INPUT -d 10.0.0.1 -j DROP\n")
        assert fw.verdict(pkt(dst="10.0.0.1")) == DROP
        assert fw.verdict(pkt(dst="10.0.0.2")) == ACCEPT

    def test_protocol(self):
        fw = firewall("-A INPUT -p udp -j DROP\n")
        assert fw.verdict(pkt(protocol="udp", dport=53, sport=50000)) == DROP
        assert fw.verdict(pkt(protocol="tcp")) == ACCEPT

    def test_destination_port(self):
        fw = firewall("-P INPUT DROP\n-A INPUT -p tcp --dport 443 -j ACCEPT\n")
        assert fw.verdict(pkt(dport=443)) == ACCEPT
        assert fw.verdict(pkt(dport=80)) == DROP

    def test_source_port(self):
        fw = firewall("-P OUTPUT DROP\n-A OUTPUT -p tcp --sport 22 -j ACCEPT\n")
        assert fw.verdict(pkt(chain="OUTPUT", sport=22)) == ACCEPT
        assert fw.verdict(pkt(chain="OUTPUT", sport=3333)) == DROP

    def test_port_range(self):
        fw = firewall("-A INPUT -p tcp --dport 8000:9000 -j DROP\n")
        assert fw.verdict(pkt(dport=8500)) == DROP
        assert fw.verdict(pkt(dport=7999)) == ACCEPT

    def test_port_match_needs_transport_port(self):
        fw = firewall("-A INPUT -p tcp --dport 80 -j DROP\n")
        assert fw.verdict(pkt(protocol="icmp", dport=None)) == ACCEPT

    def test_negated_source(self):
        fw = firewall("-A INPUT ! -s 10.0.0.7 -p icmp -j DROP\n")
        assert fw.verdict(pkt(protocol="icmp", src="10.0.0.8")) == DROP
        assert fw.verdict(pkt(protocol="icmp", src="10.0.0.7")) == ACCEPT

    def test_negated_destination(self):
        fw = firewall("-A INPUT -s 172.16.0.0/16 ! -d 172.16.5.5 -j DROP\n")
        assert fw.verdict(pkt(src="172.16.1.1", dst="172.16.5.6")) == DROP
        assert fw.verdict(pkt(src="172.16.1.1", dst="172.16.5.5")) == ACCEPT

    def test_negated_protocol(self):
        fw = firewall("-A INPUT ! -p tcp -j DROP\n")
        assert fw.verdict(pkt(protocol="udp", dport=53)) == DROP
        assert fw.verdict(pkt(protocol="tcp")) == ACCEPT

    def test_negated_port(self):
        fw = firewall("-A INPUT -p tcp ! --dport 22 -j DROP\n")
        assert fw.verdict(pkt(dport=80)) == DROP
        assert fw.verdict(pkt(dport=22)) == ACCEPT

    def test_connection_state_match(self):
        fw = firewall("-A INPUT -m state --state NEW -j DROP\n")
        assert fw.verdict(pkt(state="NEW")) == DROP
        assert fw.verdict(pkt(state="ESTABLISHED")) == ACCEPT

    def test_stateful_rule_never_matches_without_state(self):
        fw = firewall("-P INPUT DROP\n-A INPUT -m state --state ESTABLISHED -j ACCEPT\n")
        assert fw.verdict(pkt(state=None)) == DROP
        assert fw.verdict(pkt(state="ESTABLISHED")) == ACCEPT


class TestChainIsolation:
    def test_rules_only_apply_to_their_chain(self):
        fw = firewall(
            "-A INPUT -j DROP\n"
            "-A OUTPUT -j ACCEPT\n"
        )
        assert fw.verdict(pkt(chain="OUTPUT")) == ACCEPT
        assert fw.verdict(pkt(chain="INPUT")) == DROP

    def test_explicit_chain_argument_overrides_packet(self):
        fw = firewall("-A FORWARD -j DROP\n-A INPUT -j ACCEPT\n")
        assert fw.verdict(pkt(chain="INPUT"), chain="FORWARD") == DROP


class TestRuleMatchesUnit:
    def test_empty_rule_matches_everything(self):
        fw = firewall("-A INPUT -j DROP\n")
        rule = fw.ruleset.rules[0]
        assert rule_matches(rule, pkt())
        assert rule_matches(rule, pkt(protocol="icmp", dport=None, sport=None))

    def test_incompatible_protocol_and_port_cannot_match(self):
        fw = firewall("-A INPUT -p tcp --dport 80 -j ACCEPT\n")
        rule = fw.ruleset.rules[0]
        assert not rule_matches(rule, pkt(protocol="udp"))


class TestFromFile:
    def test_loads_fixture(self):
        fw = Firewall.from_file("tests/fixtures/rules.v4")
        assert fw.verdict(pkt(dport=22)) == ACCEPT
        assert fw.verdict(pkt(dport=80, src="192.168.1.50")) == ACCEPT
        assert fw.verdict(pkt(dport=80, src="203.0.113.1")) == DROP  # policy
        established = pkt(protocol="tcp", dport=9999, state="ESTABLISHED")
        assert fw.verdict(established) == ACCEPT

    def test_fixture_icmp_negated_source_rule_is_hit(self):
        fw = Firewall.from_file("tests/fixtures/rules.v4")
        evaluation = fw.evaluate(pkt(protocol="icmp", dport=None, sport=None, src="10.9.9.9"))
        assert evaluation.verdict == DROP
        assert evaluation.rule is not None
        assert evaluation.rule.index == 3


@pytest.mark.parametrize("target", [ACCEPT, DROP])
def test_every_target_value_is_enforced(target):
    fw = firewall(f"-A INPUT -j {target}\n")
    assert fw.verdict(pkt()) == target
