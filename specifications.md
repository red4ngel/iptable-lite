# iptable-lite — Project Specification

## 1. Project Overview

Goal: write a small **iptable-lite** packet filter with stateful connection tracking, inspired by `iptables`.

Linux only, since NetfilterQueue support is required.

## 2. Scope Boundaries

### In scope

- Rule-based packet filtering
- Stateful connection tracking
- Per-rule rate limiting via iptables `-m limit` semantics
- Python implementation
- Shared GitHub repository
- Live demo (5 min)

### Out of scope

- Kernel-level or netfilter integration
- Production-grade performance
- IPv6 support
- Graphical interface
- Deep packet inspection (Suricata-style IDS/IPS)
- Paid tools or infrastructure

## 3. Functional Requirements

| ID | Requirement | Status |
|------|-------------|--------|
| FR-1 | Load filtering rules from a configuration source. | Implemented |
| FR-2 | Match packets against rules in order. | Implemented |
| FR-3 | Apply one verdict per packet: `ACCEPT` or `DROP`. | Implemented |
| FR-4 | Match on header fields, e.g. source/destination IP, ports, protocol. | Implemented |
| FR-5 | Apply a default policy when no rule matches. | Implemented |
| FR-6 | Track connections in a state table. | Implemented |
| FR-7 | Classify packets by connection state: `NEW` or `ESTABLISHED`. | Implemented |
| FR-8 | Expire idle state entries. | Implemented |
| FR-9 | Allow rules to reference connection state. | Implemented |
| FR-10 | Log each verdict. | Implemented |
| FR-11 | Rate-limit matching with iptables `-m limit` / `--limit` / `--limit-burst`. | Implemented |
| FR-12 | Emit throttled security events separate from verdict logs. | Implemented |
| FR-13 | Mirror alerts to the alert logger and optional append-only file. | Implemented |
| FR-14 | Detect rapid per-source TCP/UDP port scans and block temporarily. | Implemented |

## 4. Technical Requirements

| Item | Requirement | Implementation |
|------|-------------|----------------|
| Language | Python | Python >= 3.10 |
| Packet source | Live capture in userspace via NFQUEUE | `nfqueue_source.py`; optional `NetfilterQueue` dependency |
| Offline testing | No-root packet checking | `cli.py --check` reads hex-encoded IPv4 packets |
| Packet library | NetfilterQueue | Optional extra: `.[nfqueue]` |
| Rule format | Same as iptables, stored in plain text | `rules.py`; accepts `iptables` commands and `iptables-save` filter output |
| Rate limiting | iptables `limit` match semantics | `ratelimit.py`; one token bucket per rule |
| Test environment | Local, with containers / userspace | `pytest` unit + userspace integration; live NFQUEUE test is opt-in |
| Version control | GitHub, shared repository | Git repository |
| Budget | Zero. Open-source tools only. | Standard library only, except optional NetfilterQueue |

### Constraints

- Total duration: about 1.5 weeks.
- Team size: three students.
- Reference tools from the course: `iptables`, Suricata.

## 5. Implemented Behavior

### 5.1 Filtering

- Rules are evaluated top-to-bottom; first match wins (FR-2).
- Every packet gets exactly one verdict: `ACCEPT` or `DROP` (FR-3).
- Match fields: source/destination IPv4 CIDR, protocol (`tcp`, `udp`, `icmp`, or number), source/destination port or range, and connection state (FR-4).
- `!` negation is supported on source, destination, protocol, ports, and state.
- Default policy is per chain; an undeclared chain falls back to `ACCEPT` (FR-5).
- Unsupported constructs are rejected at parse time with `line N:` errors: interface matches, fragments, user-defined chains, non-`ACCEPT`/`DROP` targets, IPv6, non-filter `-t` tables.
- Non-filter tables in `iptables-save` input are skipped.

### 5.2 Connection state

- State table key is direction-agnostic: `(endpoint_a, endpoint_b, protocol)` (FR-6).
- Only `NEW` and `ESTABLISHED` are produced (FR-7):
  - first packet of a flow -> `NEW`
  - any later packet of the same flow in either direction -> `ESTABLISHED`
- Idle entries expire lazily using a monotonic clock; default timeout is `300s` (FR-8).
- `--state` / `--ctstate` rules match the annotated state (FR-9).
- `--no-stateful` disables tracking; state rules then never match.
- `--state-timeout SECONDS` configures idle expiry.

State classification is read-only. A flow is recorded or refreshed only after `ACCEPT`; a dropped first packet remains `NEW` on retry. The table defaults to 65,536 entries and never evicts live flows.

### 5.3 Rate limiting

- Syntax: `-m limit --limit RATE --limit-burst N` (FR-11).
- `--limit-burst` defaults to `5`; `--limit` defaults to `3/hour` (iptables defaults).
- Rate format: `N/second|minute|hour|day`; aliases `s`, `sec`, `m`, `min`, `h`, `hr`, `d` are accepted.
- `--limit` / `--limit-burst` may be used without writing `-m limit`; `-m limit` alone uses defaults.
- Each rule gets an independent token bucket:
  - starts full with `burst` tokens
  - spends one token per matching packet
  - refills at `rate` tokens/second, capped at `burst`
- Rate is checked only after all other rule fields match, so non-matching packets spend no tokens.
- When the bucket is empty the rule acts as non-matching: evaluation falls through to later rules, then the default policy.
- `!` negation of rate-limit options is rejected.

### 5.4 Observability

- Exactly one structured log line per verdict (FR-10):
  `verdict=<...> chain=<...> packet=<...> state=<...> reason=<...>`
- Log level is configurable with `--log-level`.
- Security events use `iptable_lite.events`; alerts are also sent to
  `iptable_lite.alerts` and optionally appended with `--alert-file PATH`.
- Repeated events are throttled by type and key (`--event-throttle`, default
  10 seconds), with suppressed counts reported on the next emitted line.

### 5.5 Scan detection

- Optional `--scan-detect` counts distinct destination/protocol/port tuples for
  NEW TCP/UDP packets in `--scan-window`; `--scan-ports` triggers a temporary
  source block for `--scan-block` seconds.
- Exempt source networks can be repeated with `--scan-exempt`; tracked sources
  are bounded by `--scan-max-sources`.
- Known limitations: scans slower than the configured window are not detected;
  spoofed source addresses can cause an innocent address to be blocked.

### 5.6 Live vs offline

- Offline: `python -m iptable_lite --rules FILE --check PACKETS.hex`.
- Live: `run_queue()` binds NFQUEUE, logs each verdict, calls `accept()`/`drop()`.
- Malformed, fragmented, IPv6, or truncated packets are logged and dropped in
  both live and offline modes.
- `--queue CHAIN=NUM` can bind several queues in one process with shared state;
  `--chain` and `--queue-num` remain available for one queue.
- `--default-policy ACCEPT|DROP` selects the fallback for undeclared chains.
- NFQUEUE payloads carry no chain metadata; live mode assumes `INPUT` unless `--chain` is given.
- `--check` also accepts `--chain`.

## 6. Module Map

| Path | Responsibility | Requirement coverage |
|------|----------------|----------------------|
| `iptable_lite/packet.py` | IPv4 header parser -> `Packet` | FR-4 |
| `iptable_lite/rules.py` | iptables-style rule/config parser | FR-1, FR-4, FR-11 |
| `iptable_lite/engine.py` | ordered matching, default policy, rate-limit check | FR-2, FR-3, FR-5, FR-11 |
| `iptable_lite/state.py` | connection state table + idle expiry | FR-6..FR-9 |
| `iptable_lite/ratelimit.py` | token-bucket rate limiter | FR-11 |
| `iptable_lite/verdicts.py` | structured verdict logging | FR-10 |
| `iptable_lite/nfqueue_source.py` | live NFQUEUE source + verdict callback | FR-3, FR-10 |
| `iptable_lite/cli.py` | CLI, offline check mode, state/limit setup | all |
| `tests/` | unit + userspace integration tests | all |

## 7. Remaining Limitations

- `RELATED`, `INVALID`, and `UNTRACKED` are accepted by the parser but never produced by the state table.
- Live NFQUEUE test requires root, `iproute2`, `iptables`, and the optional `NetfilterQueue` package; it is skipped otherwise.
- No interface matching, fragments, user-defined chains, DNAT/LOG/other targets, IPv6, non-filter tables, or ICMP type matching.
- No persistence of state or rate buckets across process restarts.
- Scan detection intentionally misses slow scans outside its window, and spoofed
  source addresses can cause an innocent source to be blocked.
- Hashlimit and event throttle state are in-memory and reset on restart.

## 8. Deliverables & Milestones

| Phase | Deliverable | Estimated timeline | Status |
|-------|-------------|--------------------|--------|
| 1. Design | High-level design (this document) | Day 1 | Complete |
| 2. Packet filter | Rule parsing and matching with verdicts | Days 2–5 | Complete |
| 3. Stateful layer | State table, expiry, state-aware rules | Days 5–8 | Complete |
| 4. Rate limiting | `-m limit` token bucket per rule | Extension | Complete |
| 5. Demo prep | Demo scenario and test traffic | Days 8–9 | Complete: `examples/demo.sh`; evidence collection in `scripts/collect_evidence.sh` |
| 6. Presentation | 15-min presentation including 5-min demo | Day 10 | Not in repository |

## 9. Test Status

- Command: `.venv/bin/pytest`
- Current rootless result: `281 passed, 1 skipped` (see
  `docs/evidence/tests.txt` and `docs/test-matrix.md`).
- The opt-in live NFQUEUE test runs in a disposable network namespace and
  checks allowed traffic, default-policy DROP, blocked traffic not reaching
  the listener, and process stop/restart. Run
  `scripts/collect_live_evidence.sh` as a user with sudo access to save logs
  in `docs/evidence/live/` (pytest output, filter log, server log, and summary).
  It is skipped in ordinary unprivileged test runs.
