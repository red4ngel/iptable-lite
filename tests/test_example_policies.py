from pathlib import Path

from iptable_lite.engine import Firewall
from iptable_lite.hashlimit import HashLimitTable
from iptable_lite.packet import Packet
from iptable_lite.rules import load_rules
from iptable_lite.state import StateTable

ROOT = Path(__file__).resolve().parents[1]


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def firewall(name, clock):
    return Firewall(load_rules(ROOT / "examples" / name),
                    state_table=StateTable(clock=clock),
                    hashlimit_table=HashLimitTable(clock=clock))


def flow(src, dst, proto, dport, sport=40000):
    return Packet(src, dst, proto, sport, dport)


def assert_accepted_with_reply(fw, packet):
    assert fw.verdict(packet) == "ACCEPT"
    reply = Packet(packet.dst, packet.src, packet.protocol,
                   packet.dport, packet.sport)
    assert fw.verdict(reply) == "ACCEPT"


def test_hospital_policy_allowed_traffic_replies_and_default_drop():
    fw = firewall("hospital.rules", Clock())
    allowed = [
        flow("10.30.1.1", "10.0.0.1", "tcp", 22),
        flow("10.10.1.1", "10.0.0.1", "tcp", 80),
        flow("10.10.1.2", "10.0.0.1", "tcp", 443),
        flow("10.10.1.3", "10.0.0.1", "udp", 53),
    ]
    for packet in allowed:
        assert_accepted_with_reply(fw, packet)
    assert fw.verdict(flow("192.0.2.1", "10.0.0.1", "tcp", 8080)) == "DROP"
    smb = flow("10.10.1.10", "10.20.1.1", "tcp", 445)
    assert fw.verdict(smb) == fw.verdict(smb) == "DROP"


def test_lab_policy_allowed_traffic_replies_and_default_drop():
    fw = firewall("lab-server.rules", Clock())
    for packet in [
        flow("10.60.1.1", "10.0.0.1", "tcp", 22),
        flow("10.60.1.2", "10.0.0.1", "tcp", 80),
        flow("10.60.1.3", "10.0.0.1", "tcp", 443),
        flow("10.60.1.4", "10.0.0.1", "udp", 53),
    ]:
        assert_accepted_with_reply(fw, packet)
    assert fw.verdict(flow("192.0.2.1", "10.0.0.1", "tcp", 8080)) == "DROP"
    smb = flow("10.60.2.1", "10.20.1.1", "tcp", 445)
    assert fw.verdict(smb) == fw.verdict(smb) == "DROP"


def test_lab_ssh_limit_is_per_host_and_only_new_connections():
    fw = firewall("lab-server.rules", Clock())
    for port in range(40000, 40005):
        assert fw.verdict(flow("10.60.3.1", "10.0.0.1", "tcp", 22, port)) == "ACCEPT"
    assert fw.verdict(flow("10.60.3.1", "10.0.0.1", "tcp", 22, 40005)) == "DROP"
    assert fw.verdict(flow("10.60.3.2", "10.0.0.1", "tcp", 22, 41000)) == "ACCEPT"
