"""Opt-in NFQUEUE proof in a disposable network namespace.

Run with ``sudo IPTABLE_LITE_LIVE=1 .venv/bin/pytest -m integration`` or use
``scripts/collect_live_evidence.sh`` to save logs under docs/evidence/live/.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
LIVE_ENABLED = os.environ.get("IPTABLE_LITE_LIVE") == "1"
ALLOWED_PORT = 39177
BLOCKED_PORT = 39178
QUEUE_NUMBER = 77


def _run(*args: str, timeout: float = 10) -> subprocess.CompletedProcess:
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=timeout)


def _client(namespace: str, port: int, timeout: float = 0.6) -> bool:
    code = (
        "import socket,sys; s=socket.socket(); s.settimeout(float(sys.argv[2])); "
        "s.connect(('127.0.0.1',int(sys.argv[1]))); print('CONNECTED'); s.close()"
    )
    result = subprocess.run(
        ["ip", "netns", "exec", namespace, sys.executable, "-c", code,
         str(port), str(timeout)],
        capture_output=True,
        text=True,
        timeout=timeout + 3,
    )
    return result.returncode == 0 and "CONNECTED" in result.stdout


def _wait_until(predicate, description: str, timeout: float = 5) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError(f"timed out waiting for {description}")


@pytest.mark.skipif(not LIVE_ENABLED, reason="set IPTABLE_LITE_LIVE=1")
@pytest.mark.skipif(os.geteuid() != 0, reason="requires root for network namespaces/NFQUEUE")
def test_nfqueue_blocked_traffic_and_process_restart(tmp_path):
    pytest.importorskip("netfilterqueue")
    if shutil.which("ip") is None or shutil.which("iptables") is None:
        pytest.skip("requires iproute2 and iptables")

    namespace = f"iptl-{uuid.uuid4().hex[:8]}"
    rules = tmp_path / "rules.v4"
    rules.write_text(
        "-P INPUT DROP\n"
        "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n"
        f"-A INPUT -p tcp --dport {ALLOWED_PORT} -j ACCEPT\n",
        encoding="utf-8",
    )
    server_log = tmp_path / "server.log"
    filter_log = tmp_path / "filter.log"
    server_code = r'''
import socket, threading, time
ports = (39177, 39178)
listeners = []
for port in ports:
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen()
    sock.settimeout(0.2)
    listeners.append((port, sock))
print("SERVER_READY", flush=True)
while True:
    for port, sock in listeners:
        try:
            conn, _ = sock.accept()
        except TimeoutError:
            continue
        print(f"REACHED destination port {port}", flush=True)
        conn.close()
'''
    evidence_dir = os.environ.get("IPTABLE_LITE_LIVE_EVIDENCE_DIR")
    server_process = None
    filter_process = None
    server_handle = server_log.open("w", encoding="utf-8")
    filter_handle = filter_log.open("w", encoding="utf-8")
    passed = False
    try:
        _run("ip", "netns", "add", namespace)
        _run("ip", "-n", namespace, "link", "set", "lo", "up")
        _run(
            "ip", "netns", "exec", namespace, "iptables", "-I", "INPUT", "1",
            "-i", "lo", "-p", "tcp", "-j", "NFQUEUE", "--queue-num",
            str(QUEUE_NUMBER),
        )
        server_process = subprocess.Popen(
            ["ip", "netns", "exec", namespace, sys.executable, "-u", "-c", server_code],
            stdout=server_handle,
            stderr=subprocess.STDOUT,
            text=True,
        )
        _wait_until(lambda: "SERVER_READY" in server_log.read_text(), "server listeners")

        def start_filter() -> subprocess.Popen:
            return subprocess.Popen(
                ["ip", "netns", "exec", namespace, sys.executable, "-m",
                 "iptable_lite", "--rules", str(rules), "--queue",
                 f"INPUT={QUEUE_NUMBER}", "--log-level", "INFO"],
                cwd=REPO_ROOT,
                env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
                stdout=filter_handle,
                stderr=subprocess.STDOUT,
                text=True,
            )

        filter_process = start_filter()
        _wait_until(lambda: _client(namespace, ALLOWED_PORT), "allowed connection")
        assert _client(namespace, BLOCKED_PORT) is False, "default-DROP traffic connected"
        _wait_until(
            lambda: f"verdict=DROP chain=INPUT" in filter_log.read_text()
            and "reason=default policy" in filter_log.read_text(),
            "default-policy DROP verdict",
        )
        reached = server_log.read_text()
        assert f"REACHED destination port {ALLOWED_PORT}" in reached
        assert f"REACHED destination port {BLOCKED_PORT}" not in reached

        filter_process.terminate()
        filter_process.wait(timeout=5)
        filter_process = None
        assert _client(namespace, ALLOWED_PORT) is False, (
            "queued traffic connected while the userspace process was stopped"
        )

        filter_process = start_filter()
        prior_count = server_log.read_text().count(f"REACHED destination port {ALLOWED_PORT}")
        _wait_until(lambda: _client(namespace, ALLOWED_PORT), "connection after restart")
        _wait_until(
            lambda: server_log.read_text().count(
                f"REACHED destination port {ALLOWED_PORT}"
            ) > prior_count,
            "server receive after restart",
        )
        assert "verdict=ACCEPT chain=INPUT" in filter_log.read_text()
        passed = True
    finally:
        if filter_process is not None:
            filter_process.terminate()
            try:
                filter_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                filter_process.kill()
                filter_process.wait(timeout=5)
        if server_process is not None:
            server_process.terminate()
            try:
                server_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_process.kill()
                server_process.wait(timeout=5)
        server_handle.close()
        filter_handle.close()
        subprocess.run(["ip", "netns", "del", namespace], capture_output=True, text=True)
        if evidence_dir:
            destination = Path(evidence_dir)
            destination.mkdir(parents=True, exist_ok=True)
            for source in (server_log, filter_log):
                if source.exists():
                    shutil.copy2(source, destination / source.name)
            summary = destination / "summary.txt"
            if passed:
                summary.write_text(
                    "result=PASS\n"
                    "Allowed traffic passed; blocked traffic did not reach the "
                    "listener; default policy DROP was logged; stopping the "
                    "filter stopped queued traffic; restarting it resumed "
                    "allowed traffic.\n",
                    encoding="utf-8",
                )
            else:
                summary.write_text(
                    "result=FAILED_OR_INCOMPLETE\n"
                    "Inspect pytest output and captured logs; this run does not "
                    "prove all live checks passed.\n",
                    encoding="utf-8",
                )
