import pytest

from iptable_lite.ratelimit import DEFAULT_BURST, DEFAULT_RATE
from iptable_lite.rules import (
    MatchSpec,
    ParseError,
    RuleSet,
    load_rules,
    parse_config,
    parse_rule,
)

FIXTURE = "tests/fixtures/rules.v4"


class TestParseSingleRule:
    def test_full_iptables_command_line(self):
        rule = parse_rule(
            "iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 80 -j ACCEPT"
        )
        assert rule.chain == "INPUT"
        assert rule.match.src == "192.168.1.0/24"
        assert rule.match.protocol == "tcp"
        assert rule.match.dport == (80, 80)
        assert rule.target == "ACCEPT"

    def test_iptables_save_style_with_module(self):
        rule = parse_rule("-A OUTPUT -p udp -m udp --dport 53 -j DROP")
        assert rule.chain == "OUTPUT"
        assert rule.match.protocol == "udp"
        assert rule.match.dport == (53, 53)
        assert rule.target == "DROP"

    def test_bare_address_gets_full_mask(self):
        rule = parse_rule("-A INPUT -s 10.0.0.5 -j DROP")
        assert rule.match.src == "10.0.0.5/32"

    def test_host_mask_is_normalized(self):
        rule = parse_rule("-A INPUT -d 192.168.1.5/24 -j DROP")
        assert rule.match.dst == "192.168.1.0/24"

    def test_destination_alias(self):
        rule = parse_rule("-A FORWARD --dst 172.16.0.0/12 -j DROP")
        assert rule.match.dst == "172.16.0.0/12"

    def test_protocol_by_number(self):
        rule = parse_rule("-A INPUT -p 6 -j ACCEPT")
        assert rule.match.protocol == "tcp"

    def test_protocol_all_is_unconstrained(self):
        rule = parse_rule("-A INPUT -p all -j ACCEPT")
        assert rule.match.protocol is None

    def test_source_port(self):
        rule = parse_rule("-A OUTPUT -p tcp --sport 1024:65535 -j ACCEPT")
        assert rule.match.sport == (1024, 65535)

    def test_port_range(self):
        rule = parse_rule("-A INPUT -p tcp --dport 1000:2000 -j DROP")
        assert rule.match.dport == (1000, 2000)

    def test_negated_source(self):
        rule = parse_rule("-A INPUT ! -s 10.0.0.7 -p icmp -j DROP")
        assert rule.match.src == "10.0.0.7/32"
        assert "src" in rule.match.negated

    def test_negated_destination_with_bang_after_option(self):
        rule = parse_rule("-A FORWARD -s 172.16.0.0/16 ! -d 172.16.5.5 -j DROP")
        assert rule.match.dst == "172.16.5.5/32"
        assert "dst" in rule.match.negated

    def test_negated_protocol(self):
        rule = parse_rule("-A INPUT ! -p tcp -j ACCEPT")
        assert rule.match.protocol == "tcp"
        assert "protocol" in rule.match.negated

    def test_connection_state_match(self):
        rule = parse_rule(
            "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
        )
        assert rule.match.states == frozenset({"ESTABLISHED", "RELATED"})

    def test_legacy_state_module(self):
        rule = parse_rule("-A INPUT -m state --state NEW -j DROP")
        assert rule.match.states == frozenset({"NEW"})

    def test_comment_is_ignored(self):
        rule = parse_rule('-A INPUT --comment "allow web" -p tcp -j ACCEPT')
        assert rule.match.protocol == "tcp"

    def test_counters_are_ignored(self):
        rule = parse_rule("-A INPUT -c 12345 678 -p tcp -j ACCEPT")
        assert rule.match.protocol == "tcp"

    def test_wait_and_table_options_stripped(self):
        rule = parse_rule("iptables -w 5 -t filter -A INPUT -j DROP")
        assert rule.chain == "INPUT"
        assert rule.target == "DROP"

    def test_empty_match_matches_everything(self):
        rule = parse_rule("-A FORWARD -j ACCEPT")
        assert rule.match.is_empty()

    def test_case_insensitive_target(self):
        assert parse_rule("-A INPUT -j accept").target == "ACCEPT"

    def test_limit_rate_and_burst(self):
        rule = parse_rule(
            "-A INPUT -p tcp -m limit --limit 5/minute --limit-burst 10 -j ACCEPT"
        )
        assert rule.match.limit is not None
        assert rule.match.limit.rate_per_second == pytest.approx(5 / 60)
        assert rule.match.limit.burst == 10

    def test_limit_module_defaults(self):
        rule = parse_rule("-A INPUT -m limit -j ACCEPT")
        assert rule.match.limit is not None
        assert rule.match.limit.rate_per_second == pytest.approx(DEFAULT_RATE)
        assert rule.match.limit.burst == DEFAULT_BURST

    def test_limit_options_imply_the_module(self):
        rule = parse_rule("-A INPUT --limit 2/second -j DROP")
        assert rule.match.limit is not None
        assert rule.match.limit.rate_per_second == pytest.approx(2)
        assert rule.match.limit.burst == DEFAULT_BURST

    @pytest.mark.parametrize(
        "rate, per_second",
        [
            ("1/second", 1),
            ("2/sec", 2),
            ("3/s", 3),
            ("60/minute", 1),
            ("120/min", 2),
            ("120/m", 2),
            ("3600/hour", 1),
            ("7200/hr", 2),
            ("7200/h", 2),
            ("86400/day", 1),
            ("86400/d", 1),
        ],
    )
    def test_rate_units(self, rate, per_second):
        rule = parse_rule(f"-A INPUT -m limit --limit {rate} -j ACCEPT")
        assert rule.match.limit.rate_per_second == pytest.approx(per_second)


class TestParseErrors:
    @pytest.mark.parametrize(
        "line, message",
        [
            ("", "empty"),
            ("-A INPUT -p tcp", "no jump target"),
            ("-A INPUT -j RETURN", "unsupported target"),
            ("-A INPUT -j DNAT --to 10.0.0.1", "unsupported target"),
            ("-A INPUT -j", "requires a target"),
            ("-s 10.0.0.1", "no jump target"),
            ("-A INPUT -s not-an-ip -j DROP", "invalid address"),
            ("-A INPUT -s 2001:db8::1 -j DROP", "IPv6"),
            ("-A INPUT -p tcp --dport 70000 -j DROP", "out of range"),
            ("-A INPUT -p tcp --dport http -j DROP", "invalid port"),
            ("-A INPUT -p gre -j DROP", "unsupported protocol"),
            ("-A INPUT -i eth0 -j DROP", "interface"),
            ("-A INPUT -o eth0 -j DROP", "interface"),
            ("-A INPUT -f -j DROP", "fragment"),
            ("-A INPUT -m addrtype -j DROP", "unsupported match module"),
            ("-A INPUT --state BOGUS -j DROP", "connection state"),
            ("-A INPUT -s 10.0.0.1 -s 10.0.0.2 -j DROP", "duplicate"),
            ("-A INPUT -j", "requires a target"),
            ("-A", "requires a chain"),
            ("-A INPUT ! -j DROP", "cannot negate a jump"),
            ("iptables -t nat -A PREROUTING -j DNAT", "filter table"),
            ("--wat 1 -j DROP", "unsupported option"),
            ("-A INPUT -m limit --limit 5 -j ACCEPT", "must look like"),
            ("-A INPUT -m limit --limit 0/minute -j ACCEPT", "positive"),
            ("-A INPUT -m limit --limit nope/minute -j ACCEPT", "invalid rate"),
            ("-A INPUT -m limit --limit 5/fortnight -j ACCEPT", "unknown rate unit"),
            ("-A INPUT -m limit --limit-burst 0 -j ACCEPT", "at least 1"),
            ("-A INPUT -m limit --limit-burst nope -j ACCEPT", "invalid burst"),
            ("-A INPUT -m limit --limit -j ACCEPT", "must look like"),
            ("-A INPUT -m limit --limit-burst -j ACCEPT", "invalid burst"),
            ("-A INPUT -m limit --limit", "requires a rate"),
            ("-A INPUT -m limit --limit-burst", "requires a count"),
            (
                "-A INPUT -m limit --limit 5/minute --limit 6/minute -j ACCEPT",
                "duplicate",
            ),
            (
                "-A INPUT -m limit --limit-burst 1 --limit-burst 2 -j ACCEPT",
                "duplicate",
            ),
            ("-A INPUT -m limit ! --limit 5/minute -j ACCEPT", "cannot negate a rate"),
            ("-A INPUT ! -m limit -j ACCEPT", "cannot negate a match module"),
        ],
    )
    def test_rejects_bad_rules(self, line, message):
        with pytest.raises(ParseError, match=message):
            parse_rule(line)

    def test_dangling_negation(self):
        with pytest.raises(ParseError, match="dangling"):
            parse_rule("-A INPUT !")

    def test_repeated_negation(self):
        with pytest.raises(ParseError, match="repeated"):
            parse_rule("-A INPUT ! ! -s 10.0.0.1 -j DROP")

    def test_policy_line_rejected_by_parse_rule(self):
        with pytest.raises(ParseError, match="policy"):
            parse_rule("-P INPUT DROP")


class TestParseConfig:
    def test_rules_keep_document_order(self):
        ruleset = load_rules(FIXTURE)
        assert [r.target for r in ruleset.rules] == [
            "ACCEPT",
            "ACCEPT",
            "ACCEPT",
            "DROP",
            "DROP",
        ]

    def test_chain_preserved_per_rule(self):
        ruleset = load_rules(FIXTURE)
        assert [r.chain for r in ruleset.rules] == [
            "INPUT",
            "INPUT",
            "INPUT",
            "INPUT",
            "FORWARD",
        ]

    def test_default_policy_from_chain_declarations(self):
        ruleset = load_rules(FIXTURE)
        assert ruleset.default_policy("INPUT") == "DROP"
        assert ruleset.default_policy("FORWARD") == "DROP"
        assert ruleset.default_policy("OUTPUT") == "ACCEPT"

    def test_undeclared_chain_falls_back_to_accept(self):
        ruleset = load_rules(FIXTURE)
        assert ruleset.default_policy("UNKNOWN") == "ACCEPT"

    def test_dash_p_policy_line(self):
        ruleset = parse_config("-P INPUT DROP\n-A INPUT -j ACCEPT\n")
        assert ruleset.policies["INPUT"] == "DROP"

    def test_comments_and_blank_lines_skipped(self):
        ruleset = parse_config("# a comment\n\n   \n-A INPUT -j ACCEPT\n")
        assert len(ruleset.rules) == 1

    def test_non_filter_tables_are_skipped(self):
        ruleset = parse_config("*nat\n-A PREROUTING -j DNAT\n*filter\n-A INPUT -j ACCEPT\nCOMMIT\n")
        assert len(ruleset.rules) == 1

    def test_plain_command_lines(self):
        ruleset = parse_config(
            "iptables -A INPUT -p tcp --dport 80 -j ACCEPT\n"
            "iptables -A INPUT -j DROP\n"
        )
        assert len(ruleset.rules) == 2

    def test_error_reports_line_number(self):
        with pytest.raises(ParseError, match="line 3"):
            parse_config("# ok\n-A INPUT -j ACCEPT\n-A INPUT -i eth0 -j DROP\n")

    def test_rule_indexes_are_sequential(self):
        ruleset = load_rules(FIXTURE)
        assert [r.index for r in ruleset.rules] == list(range(5))

    def test_ruleset_defaults(self):
        assert RuleSet().default_policy("INPUT") == "ACCEPT"

    def test_match_spec_is_immutable(self):
        spec = MatchSpec(src="10.0.0.1/32")
        with pytest.raises(Exception):
            spec.src = "10.0.0.2/32"  # type: ignore[misc]
