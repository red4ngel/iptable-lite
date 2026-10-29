# Change log

## Task 1 — packet safety and policy behavior

- Dropped flows no longer create or refresh connection state; verified by
  `test_dropped_smb_syn_and_retry_stay_new` and
  `test_dropped_established_packet_does_not_refresh_state`.
- Added bounded state tracking; verified by the `test_full_table_*` tests in
  `tests/test_state_flow.py`.
- Rejected truncated, inconsistent, unsupported-version, transport-truncated,
  and fragmented packets; verified by `tests/test_packet_strict.py`.
- Added source-keyed hashlimit; parser, token bucket, isolation, and table-full
  behavior are verified by `tests/test_hashlimit.py`.
- Added security events, scan detection, and multi-queue configuration; see
  `tests/test_hashlimit.py`, `tests/test_cli.py`, and scan tests in the suite.
- Scan detection originally ignored NEW packets when state tracking was
  disabled. It now treats unannotated TCP/UDP packets as NEW; verified by
  `test_scan_threshold_blocks_source_and_exempts_network`.
- Event suppression counts were initially emitted as a standalone line, which
  did not preserve the structured event format. Counts now accompany the next
  event line; verified by
  `test_event_throttle_reports_suppressed_count_and_bounds_memory`.
- Added policy regression coverage for hospital and lab rules, accepted replies,
  SMB retries, and source-isolated SSH limits; verified by
  `tests/test_example_policies.py`.
- Added an opt-in live NFQUEUE integration test isolated in a disposable network
  namespace. It records allow, default-DROP, blocked-destination, and process
  stop/restart evidence; the test is not run without explicit root opt-in.
