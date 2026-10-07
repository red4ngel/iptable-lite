"""End-to-end test: rules file + packets -> CLI verdicts, no root needed."""

import os
import subprocess
import sys
from pathlib import Path

from packet_helpers import build_ipv4, tcp_payload, udp_payload

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES = REPO_ROOT / "tests" / "fixtures" / "rules.v4"


def run_cli(*args):
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT)}
    return subprocess.run(
        [sys.executable, "-m", "iptable_lite", *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=REPO_ROOT,
    )


def test_full_pipeline_produces_expected_verdicts(tmp_path):
    packets = tmp_path / "packets.hex"
    packets.write_text(
        "\n".join(
            [
                build_ipv4(src="203.0.113.10", payload=tcp_payload(dport=22)).hex(),
                build_ipv4(src="192.168.1.50", payload=tcp_payload(dport=80)).hex(),
                build_ipv4(src="203.0.113.10", payload=tcp_payload(dport=80)).hex(),
                build_ipv4(
                    src="10.9.9.9", protocol=1, payload=b"\x08\x00" + b"\x00" * 6
                ).hex(),
                build_ipv4(payload=udp_payload(dport=53)).hex(),
            ]
        )
    )

    result = run_cli("--rules", str(RULES), "--check", str(packets))
    assert result.returncode == 0, result.stderr

    verdict_lines = [
        line for line in result.stdout.splitlines() if not line.startswith("#")
    ]
    verdicts = [line.split("\t", 1)[0] for line in verdict_lines]
    assert verdicts == ["ACCEPT", "ACCEPT", "DROP", "DROP", "DROP"]

    # ssh rule, web rule, default policy, icmp rule, default policy
    assert "rule[1]" in verdict_lines[0]
    assert "rule[2]" in verdict_lines[1]
    assert "default policy" in verdict_lines[2]
    assert "rule[3]" in verdict_lines[3]


def test_full_pipeline_logs_every_verdict(tmp_path):
    packets = tmp_path / "packets.hex"
    packets.write_text(build_ipv4(payload=tcp_payload(dport=22)).hex() + "\n")

    result = run_cli("--rules", str(RULES), "--check", str(packets))
    assert result.returncode == 0, result.stderr
    assert "verdict=ACCEPT" in result.stderr
    assert "chain=INPUT" in result.stderr


def test_pipeline_rejects_broken_rules(tmp_path):
    rules = tmp_path / "broken.rules"
    rules.write_text("-A INPUT -i eth0 -j ACCEPT\n")
    packets = tmp_path / "packets.hex"
    packets.write_text(build_ipv4(payload=tcp_payload()).hex() + "\n")

    result = run_cli("--rules", str(rules), "--check", str(packets))
    assert result.returncode == 2
    assert "line 1" in result.stderr
