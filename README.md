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
- Rate limiting through `-m limit --limit RATE --limit-burst N`, with an
  independent token bucket per rule
- One structured log line per verdict (FR-10)
- Strict IPv4 parsing; malformed packets and every fragment are dropped
- Per-source `hashlimit`, throttled events and alerts, and optional port-scan
  detection
- Bounded connection and rate-limit tables; multiple live NFQUEUE mappings
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

## Rate limiting

The iptables `limit` match is backed by a token bucket per rule:

```text
-A INPUT -p tcp --dport 80 -m limit --limit 30/minute --limit-burst 60 -j ACCEPT
-A INPUT -p tcp --dport 80 -j DROP
```

`--limit` accepts `N/second|minute|hour|day` (short forms such as `/s`, `/min`,
`/hr`, `/d` also work) and defaults to `3/hour`; `--limit-burst` defaults to
`5`. A bucket starts full, spends one token per matching packet, and refills at
the configured rate. Once the budget is empty the rule stops matching, so the
packet falls through to later rules (or the default policy). Packets that do
not match the rule's other fields never spend tokens.

## Usage

Live filtering (root required):

```bash
sudo iptables -I INPUT -j NFQUEUE --queue-num 0
sudo .venv/bin/python -m iptable_lite --rules rules.v4 --queue-num 0
```

For multiple chains, pass `--queue INPUT=0 --queue OUTPUT=1`. Install the
corresponding NFQUEUE rules with `examples/setup-input-queue.sh` and
`examples/setup-output-queue.sh`; neither uses queue bypass. The process must
stay running for queued traffic to receive verdicts.

All CLI flags:

- `--rules FILE` (required), `--check FILE` (offline hex packets)
- `--queue CHAIN=NUM` (repeatable), or legacy `--chain CHAIN --queue-num N`
- `--state-timeout SECONDS` (300), `--state-max-entries N` (65536),
  `--no-stateful`
- `--default-policy ACCEPT|DROP` (fallback for undeclared chains: ACCEPT)
- `--scan-detect`, `--scan-ports N` (10), `--scan-window SECONDS` (10),
  `--scan-block SECONDS` (60), `--scan-max-sources N` (4096), repeatable
  `--scan-exempt CIDR`
- `--alert-file PATH`, `--event-throttle SECONDS` (10),
  `--log-level DEBUG|INFO|WARNING|ERROR`

The `hashlimit` rule options are `--hashlimit-name`, exactly one of
`--hashlimit-upto`/`--hashlimit-above`, and optional `--hashlimit-burst`,
`--hashlimit-mode`, `--hashlimit-htable-max`, `--hashlimit-htable-expire`.
Defaults are burst 5, mode `srcip`, max 4096 keys, and expiry 60000 ms.

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
examples/demo.sh                # non-interactive offline feature demo
scripts/collect_evidence.sh     # write demo and test outputs under docs/evidence/
scripts/collect_live_evidence.sh # root: isolated live evidence for allow/drop/stop/restart
```

The offline evidence script saves the test summary and demo output to
`docs/evidence/tests.txt` and `docs/evidence/demo.txt`. The live evidence script
uses `sudo` only for the opt-in test. It creates a temporary network namespace,
runs allow and default-DROP probes, stops and restarts the filter, and always
removes the namespace. Its pytest output, filter log, server log, and summary
are copied to `docs/evidence/live/`. The host firewall is not modified.

## Project layout

| Path | Contents |
|------|----------|
| `iptable_lite/packet.py` | IPv4 header parser → `Packet` |
| `iptable_lite/rules.py` | iptables-style rule parsing (FR-1, FR-4) |
| `iptable_lite/engine.py` | matching loop + verdicts (FR-2, FR-3, FR-5) |
| `iptable_lite/state.py` | connection state table (FR-6..FR-9) |
| `iptable_lite/ratelimit.py` | per-rule token-bucket rate limiter |
| `iptable_lite/verdicts.py` | verdict logging (FR-10) |
| `iptable_lite/nfqueue_source.py` | NFQUEUE packet source |
| `iptable_lite/cli.py` | command-line interface |
| `tests/` | pytest suite (unit + integration) |
