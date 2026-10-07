# iptable-lite

A small **stateful packet filter** inspired by `iptables`, written in Python.
It reads plain-text iptables-style rules, classifies packets in userspace via
**NFQUEUE**, tracks connection state, and logs every verdict.

Linux only (NetfilterQueue requirement). Zero budget: open-source tools only.

## Features

- Rule-based packet filtering — first match wins, `ACCEPT`/`DROP` verdicts,
  per-chain default policy (FR-1..FR-5)
- Matches on source/destination IP (CIDR), protocol, source/destination
  ports (single or ranges), with `!` negation (FR-4)
- Stateful layer: `--state` / `--ctstate` match support, connection state
  table with idle expiry (FR-6..FR-9)
- One structured log line per verdict (FR-10)
- Live capture through NFQUEUE, or offline `--check` mode for
  root-less testing and demos

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev,nfqueue]'   # nfqueue extra needs root headers
```

`NetfilterQueue` compiles against libnetfilter-queue; on Debian/Ubuntu:

```bash
sudo apt install libnetfilter-queue-dev
```

## Rule files

Rules use plain `iptables` command syntax or `iptables-save` output for the
filter table:

```text
*filter
:INPUT DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -s 192.168.1.0/24 -p tcp --dport 80 -j ACCEPT
-A INPUT ! -s 10.0.0.7 -p icmp -j DROP
COMMIT
```

Anything that cannot be enforced faithfully (interface matches, fragments,
user-defined chains, non-`ACCEPT`/`DROP` targets, IPv6) is rejected with a
`line N:` error instead of being silently ignored.

## Usage

Live filtering (root required):

```bash
sudo iptables -I INPUT -j NFQUEUE --queue-num 0
sudo .venv/bin/python -m iptable_lite --rules rules.v4 --queue-num 0
```

Offline verdict check (no root, good for tests/demos):

```bash
python -m iptable_lite --rules rules.v4 --check packets.hex
```

`packets.hex` holds one raw IPv4 packet per line in hex, e.g.
`45000028...` (blank lines and `#` comments allowed).

## Verdict log

Every packet produces exactly one line:

```text
2026-10-07 15:30:00 INFO iptable_lite.verdict: verdict=ACCEPT chain=INPUT packet='203.0.113.10:51344 -> 10.0.0.1:22 proto=tcp' state=- reason=rule[1] -A INPUT -p tcp --dport 22 -j ACCEPT
```

## Tests

```bash
.venv/bin/pytest                # unit + userspace integration tests
.venv/bin/pytest -m integration # live NFQUEUE test (skips unless IPTABLE_LITE_LIVE=1)
```

## Project layout

| Path | Contents |
|------|----------|
| `iptable_lite/packet.py` | IPv4 header parser → `Packet` |
| `iptable_lite/rules.py` | iptables-style rule parsing (FR-1, FR-4) |
| `iptable_lite/engine.py` | matching loop + verdicts (FR-2, FR-3, FR-5) |
| `iptable_lite/state.py` | connection state table (FR-6..FR-9) |
| `iptable_lite/verdicts.py` | verdict logging (FR-10) |
| `iptable_lite/nfqueue_source.py` | NFQUEUE packet source |
| `iptable_lite/cli.py` | command-line interface |
| `tests/` | pytest suite (unit + integration) |
