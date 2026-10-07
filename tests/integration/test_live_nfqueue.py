"""Opt-in live test against a real NFQUEUE (needs root + NetfilterQueue).

Enable with: sudo IPTABLE_LITE_LIVE=1 .venv/bin/pytest -m integration
"""

import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
LIVE_ENABLED = os.environ.get("IPTABLE_LITE_LIVE") == "1"

PORT = 9917  # test-only listening port


@pytest.mark.skipif(
    not LIVE_ENABLED,
    reason="set IPTABLE_LITE_LIVE=1 as root with NetfilterQueue installed",
)
@pytest.mark.skipif(os.geteuid() != 0, reason="requires root for iptables/NFQUEUE")
def test_live_nfqueue_accepts_traffic(tmp_path):
    pytest.importorskip("netfilterqueue")

    rules = tmp_path / "rules.v4"
    rules.write_text(
        "-P INPUT DROP\n"
        f"-A INPUT -p tcp --dport {PORT} -j ACCEPT\n"
        "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n"
    )
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", PORT))
    listener.listen(1)

    queue_rule = [
        "iptables",
        "-I",
        "INPUT",
        "-p",
        "tcp",
        "--dport",
        str(PORT),
        "-j",
        "NFQUEUE",
        "--queue-num",
        "0",
    ]
    subprocess.run(queue_rule, check=True)

    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT)}
    filter_proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "iptable_lite",
            "--rules",
            str(rules),
            "--queue-num",
            "0",
            "--log-level",
            "DEBUG",
        ],
        env=env,
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    time.sleep(1.0)
    try:
        def connect():
            client = socket.create_connection(("127.0.0.1", PORT), timeout=5)
            client.sendall(b"ping")
            client.close()

        worker = threading.Thread(target=connect)
        worker.start()
        connection, _ = listener.accept()
        connection.recv(4)
        connection.close()
        worker.join(timeout=5)
    finally:
        filter_proc.terminate()
        stdout, stderr = filter_proc.communicate(timeout=10)
        subprocess.run(["iptables", "-D", "INPUT", *queue_rule[3:]], check=False)
        listener.close()

    assert "verdict=ACCEPT" in stderr, stderr
