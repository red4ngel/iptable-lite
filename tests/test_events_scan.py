import logging

from iptable_lite.engine import Firewall
from iptable_lite.events import EventEmitter
from iptable_lite.packet import Packet
from iptable_lite.rules import parse_config
from iptable_lite.scan import ScanDetector


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def test_event_throttle_reports_suppressed_count_and_bounds_memory(caplog):
    clock = Clock()
    emitter = EventEmitter(throttle=10, throttle_memory=1, clock=clock)
    with caplog.at_level(logging.WARNING, logger="iptable_lite.events"):
        emitter.emit("rate_limit_hit", "192.0.2.1", key="one")
        emitter.emit("rate_limit_hit", "192.0.2.1", key="one")
        clock.now = 10
        emitter.emit("rate_limit_hit", "192.0.2.1", key="one")
        emitter.emit("rate_limit_hit", "192.0.2.2", key="two")
    assert len(emitter) <= 1
    assert any("suppressed=1" in record.getMessage() for record in caplog.records)


def test_alert_is_appended(tmp_path, caplog):
    target = tmp_path / "alerts.log"
    emitter = EventEmitter(alert_file=str(target), clock=Clock())
    with caplog.at_level(logging.WARNING, logger="iptable_lite.alerts"):
        emitter.emit("scan_detected", "192.0.2.9", detail="ports=10")
    assert "event=scan_detected severity=alert" in target.read_text()
    assert any("event=scan_detected" in record.getMessage() for record in caplog.records)


def test_scan_threshold_blocks_source_and_exempts_network(caplog):
    clock = Clock()
    events = EventEmitter(clock=clock)
    detector = ScanDetector(ports=3, window=10, block=5, max_sources=3,
                            exempt=["192.0.2.0/24"], clock=clock, events=events)
    fw = Firewall(parse_config(":INPUT DROP\n"), events=events, scan_detector=detector)
    scan = [Packet("198.51.100.9", f"203.0.113.{n}", "tcp", 1234, 1000+n)
            for n in range(1, 4)]
    with caplog.at_level(logging.WARNING, logger="iptable_lite.events"):
        assert [fw.verdict(packet) for packet in scan] == ["DROP", "DROP", "DROP"]
        assert detector.blocked("198.51.100.9")
        assert fw.verdict(Packet("198.51.100.9", "203.0.113.99", "tcp", 5, 80,
                                 state="ESTABLISHED")) == "DROP"
        for n in range(3):
            fw.verdict(Packet("192.0.2.1", f"203.0.113.{n+1}", "tcp", 5, 80))
        assert not detector.blocked("192.0.2.1")
    assert any("event=scan_detected" in record.getMessage() for record in caplog.records)
    clock.now = 5
    assert not detector.blocked("198.51.100.9")


def test_scan_active_blocks_are_not_evicted_by_new_sources():
    clock = Clock()
    detector = ScanDetector(ports=1, max_sources=1, clock=clock)
    first = Packet("198.51.100.1", "203.0.113.1", "tcp", 1, 1)
    second = Packet("198.51.100.2", "203.0.113.2", "tcp", 1, 2)
    assert detector.observe(first)
    assert detector.blocked(first.src)
    assert not detector.observe(second)
    assert detector.blocked(first.src)
