# iptable-lite — Project Specification

## 1. Project Overview

Goal: write a small **iptable-lite** packet filter with stateful connection tracking, inspired by `iptables`.

Linux only, since NetfilterQueue support is required.

## 2. Scope Boundaries

### In scope

- Rule-based packet filtering
- Stateful connection tracking
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

### Packet filter

| ID | Requirement |
|------|-------------|
| FR-1 | Load filtering rules from a configuration source. |
| FR-2 | Match packets against rules in order. |
| FR-3 | Apply one verdict per packet: `ACCEPT` or `DROP`. |
| FR-4 | Match on header fields, e.g. source/destination IP, ports, protocol. |
| FR-5 | Apply a default policy when no rule matches. |

### Stateful firewall

| ID | Requirement |
|------|-------------|
| FR-6 | Track connections in a state table. |
| FR-7 | Classify packets by connection state: `NEW` or `ESTABLISHED`. |
| FR-8 | Expire idle state entries. |
| FR-9 | Allow rules to reference connection state. |

### Observability

| ID | Requirement |
|-------|-------------|
| FR-10 | Log each verdict. |

## 4. Technical Requirements

| Item | Requirement |
|------|-------------|
| Language | Python |
| Packet source | Live capture in userspace via NFQUEUE |
| Packet library | NetfilterQueue |
| Rule format | Same as iptables, stored in plain text |
| Test environment | Local, with containers / userspace |
| Version control | GitHub, shared repository |
| Budget | Zero. Open-source tools only. |

### Constraints

- Total duration: about 1.5 weeks.
- Team size: three students.
- Reference tools from the course: `iptables`, Suricata.

## 5. Deliverables & Milestones

| Phase | Deliverable | Estimated timeline |
|-------|-------------|--------------------|
| 1. Design | High-level design (this document) | Day 1 |
| 2. Packet filter | Rule parsing and matching with verdicts | Days 2–5 |
| 3. Stateful layer | State table, expiry, state-aware rules | Days 5–8 |
| 4. Demo prep | Demo scenario and test traffic | Days 8–9 |
| 5. Presentation | 15-min presentation including 5-min demo | Day 10 |
