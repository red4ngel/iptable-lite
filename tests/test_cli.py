import logging

import pytest

from iptable_lite.cli import main
from iptable_lite.verdicts import LOGGER_NAME
from packet_helpers import build_ipv4, tcp_payload


@pytest.fixture(autouse=True)
def reset_verdict_logger():
    target = logging.getLogger(LOGGER_NAME)
    target.handlers.clear()
    target.setLevel(logging.NOTSET)
    target.propagate = True
    yield
    target.handlers.clear()
    target.setLevel(logging.NOTSET)
    target.propagate = True


def write_rules(tmp_path, text):
    path = tmp_path / "rules.v4"
    path.write_text(text)
    return str(path)


def write_packets(tmp_path, packets):
    path = tmp_path / "packets.hex"
    path.write_text("\n".join(p.hex() for p in packets) + "\n")
    return str(path)


class TestArgumentHandling:
    def test_rules_argument_is_required(self):
        with pytest.raises(SystemExit) as exc:
            main([])
        assert exc.value.code == 2

    def test_missing_rule_file(self, capsys):
        assert main(["--rules", "/nonexistent/rules.v4"]) == 2
        assert "rule file not found" in capsys.readouterr().err

    def test_invalid_rule_file_reports_line(self, tmp_path, capsys):
        rules = write_rules(tmp_path, "-A INPUT -j ACCEPT\n-A INPUT -i eth0 -j DROP\n")
        assert main(["--rules", rules]) == 2
        assert "line 2" in capsys.readouterr().err

    def test_nfqueue_mode_without_library_fails_cleanly(self, tmp_path, capsys):
        rules = write_rules(tmp_path, "-A INPUT -j ACCEPT\n")
        assert main(["--rules", rules]) == 2
        assert "NetfilterQueue is required" in capsys.readouterr().err


class TestCheckMode:
    def test_prints_verdicts_for_hex_packets(self, tmp_path, capsys):
        rules = write_rules(
            tmp_path,
            "-P INPUT DROP\n-A INPUT -p tcp --dport 22 -j ACCEPT\n",
        )
        packets = write_packets(
            tmp_path,
            [
                build_ipv4(payload=tcp_payload(dport=22)),
                build_ipv4(payload=tcp_payload(dport=8080)),
            ],
        )
        assert main(["--rules", rules, "--check", packets]) == 0
        out = capsys.readouterr().out
        assert "ACCEPT" in out
        assert "DROP" in out
        assert out.strip().splitlines()[-1].startswith("# 2 packet(s)")

    def test_invalid_hex_fails(self, tmp_path, capsys):
        rules = write_rules(tmp_path, "-A INPUT -j ACCEPT\n")
        packets = tmp_path / "packets.hex"
        packets.write_text("nothex\n")
        assert main(["--rules", rules, "--check", str(packets)]) == 2
        assert "invalid hex" in capsys.readouterr().err

    def test_chain_override(self, tmp_path, capsys):
        rules = write_rules(
            tmp_path,
            "-A FORWARD -j DROP\n-A INPUT -j ACCEPT\n",
        )
        packets = write_packets(tmp_path, [build_ipv4(payload=tcp_payload())])
        assert main(["--rules", rules, "--check", packets, "--chain", "FORWARD"]) == 0
        assert capsys.readouterr().out.splitlines()[0].startswith("DROP")

    def test_comments_and_blank_lines_ignored(self, tmp_path, capsys):
        rules = write_rules(tmp_path, "-A INPUT -j DROP\n")
        packets = tmp_path / "packets.hex"
        packets.write_text(
            "# a comment\n\n"
            + build_ipv4(payload=tcp_payload()).hex()
            + "  # trailing comment\n"
        )
        assert main(["--rules", rules, "--check", str(packets)]) == 0
        assert capsys.readouterr().out.splitlines()[0].startswith("DROP")

    def test_verdict_logging_active_in_check_mode(self, tmp_path, capsys):
        rules = write_rules(tmp_path, "-P INPUT DROP\n")
        packets = write_packets(tmp_path, [build_ipv4(payload=tcp_payload())])
        assert main(["--rules", rules, "--check", packets]) == 0
        captured = capsys.readouterr()
        assert "verdict=DROP" in captured.err


def flow_and_reply():
    forward = build_ipv4(
        src="203.0.113.10", dst="10.0.0.1", payload=tcp_payload(sport=51000, dport=80)
    )
    backward = build_ipv4(
        src="10.0.0.1", dst="203.0.113.10", payload=tcp_payload(sport=80, dport=51000)
    )
    return forward, backward


class TestStatefulMode:
    RULES = (
        "-P INPUT DROP\n"
        "-A INPUT -m state --state ESTABLISHED -j ACCEPT\n"
    )

    def test_stateful_enabled_by_default(self, tmp_path, capsys):
        rules = write_rules(tmp_path, self.RULES)
        forward, backward = flow_and_reply()
        packets = write_packets(tmp_path, [forward, backward])
        assert main(["--rules", rules, "--check", packets]) == 0
        lines = [l for l in capsys.readouterr().out.splitlines() if not l.startswith("#")]
        verdicts = [l.split("\t", 1)[0] for l in lines]
        assert verdicts == ["DROP", "ACCEPT"]  # NEW then ESTABLISHED

    def test_no_stateful_disables_tracking(self, tmp_path, capsys):
        rules = write_rules(tmp_path, self.RULES)
        forward, backward = flow_and_reply()
        packets = write_packets(tmp_path, [forward, backward])
        assert main(["--rules", rules, "--check", packets, "--no-stateful"]) == 0
        lines = [l for l in capsys.readouterr().out.splitlines() if not l.startswith("#")]
        verdicts = [l.split("\t", 1)[0] for l in lines]
        assert verdicts == ["DROP", "DROP"]

    def test_invalid_state_timeout_rejected(self, tmp_path, capsys):
        rules = write_rules(tmp_path, self.RULES)
        packets = write_packets(tmp_path, [build_ipv4(payload=tcp_payload())])
        assert (
            main(
                ["--rules", rules, "--check", packets, "--state-timeout", "0"]
            )
            == 2
        )
        assert "timeout must be positive" in capsys.readouterr().err

    def test_states_appear_in_logs(self, tmp_path, capsys):
        rules = write_rules(tmp_path, self.RULES)
        forward, backward = flow_and_reply()
        packets = write_packets(tmp_path, [forward, backward])
        assert main(["--rules", rules, "--check", packets]) == 0
        err = capsys.readouterr().err
        assert "state=NEW" in err
        assert "state=ESTABLISHED" in err
