# Test matrix

Full run: `.venv/bin/pytest -q` → **279 passed, 1 skipped**. The skipped test is
the opt-in live NFQUEUE test; it was not run because `IPTABLE_LITE_LIVE=1` and
root namespace setup were not enabled. “Not covered” marks requirements for
which the current suite has no direct assertion.

| ID | category (normal/negative/adversarial/recovery) | threat or requirement | input | expected | actual | result | test name |
|---|---|---|---|---|---|---|---|
| T-1 | normal | ordered rules and default policy | matching and unmatched packets | first match / policy | as expected | pass | `test_first_matching_rule_wins`; `test_accept_policy_when_nothing_matches` |
| T-2 | normal | state is bidirectional after ACCEPT | accepted flow then reverse packet | NEW then ESTABLISHED | as expected | pass | `test_accepted_flow_creates_state_and_reply_is_established` |
| T-3 | adversarial | dropped first packet cannot seed state | SMB SYN and retry | both DROP, NEW | as expected | pass | `test_dropped_smb_syn_and_retry_stay_new` |
| T-4 | adversarial | bounded state table preserves live flows | exceed max entries | refuse tracking, alert | as expected | pass | `test_full_table_keeps_live_entries_and_raises_alert` |
| T-5 | negative | strict parsing and fragment rejection | malformed/truncated/fragmented IPv4 | DROP | parser raises safe parse error | pass | `test_*` in `tests/test_packet_strict.py`; NFQUEUE malformed tests |
| T-6 | adversarial | independent per-source hashlimit | rapid SSH from two sources | one limited, other unaffected | as expected | pass | `test_one_source_does_not_affect_another` |
| T-7 | recovery | table entries expire before capacity refusal | expired entry plus new flow | new flow tracked | as expected | pass | `test_expired_entries_are_purged_before_refusing` |
| FR-1 | normal | load rules | valid rule file | parsed rules | as expected | pass | `test_loads_fixture`; `test_plain_command_lines` |
| FR-2 | normal | ordered matching | overlapping rules | first match wins | as expected | pass | `test_first_matching_rule_wins` |
| FR-3 | adversarial | unsafe evaluation fails closed | unexpected evaluation error | DROP and event | as expected | pass | `test_verdict_is_logged_for_every_nfqueue_packet` (callback safety); direct injected-error coverage: not covered |
| FR-4 | normal | header matching | IPv4 addresses/protocol/ports | match correct fields | as expected | pass | `tests/test_engine.py` field-match tests |
| FR-5 | normal | chain default policy | declared and undeclared chains | configured fallback | as expected | pass | `test_drop_policy_from_config`; `test_undeclared_chain_falls_back_to_accept` |
| FR-6 | normal | connection tracking | accepted flow | entry recorded | as expected | pass | `test_accepted_flow_creates_state_and_reply_is_established` |
| FR-7 | normal | state classification is read-only | dropped flow retry | remains NEW | as expected | pass | `test_dropped_smb_syn_and_retry_stay_new` |
| FR-8 | recovery | idle state expiry | fake clock beyond timeout | expired flow starts NEW | as expected | pass | `test_expired_entries_are_purged_before_refusing`; `test_idle_entries_expire` |
| FR-9 | normal | state rules | forward then reverse flow | reply ESTABLISHED | as expected | pass | `test_accepted_flow_creates_state_and_reply_is_established` |
| FR-10 | normal | one verdict log per packet | packet batch | one line each | as expected | pass | `test_each_verdict_is_logged_exactly_once`; `test_every_packet_gets_its_own_log_line` |
| FR-11 | adversarial | rate and hashlimit enforcement | token exhaustion, distinct sources | exhausted key limited | as expected | pass | `tests/test_ratelimit.py`; `tests/test_hashlimit.py` |
| FR-12 | normal | event formatting and throttle | repeated event with fake clock | throttled with suppressed count | as expected | pass | `test_event_throttle_reports_suppressed_count_and_bounds_memory` |
| FR-13 | normal | alert logger and file | alert event | mirrored and appended | as expected | pass | `test_alert_is_appended`; `test_hashlimit_table_full_alert_goes_to_alert_logger` |
| FR-14 | adversarial | scan threshold and source block | distinct NEW ports, exemption, and expiry | alert and block; exempt source unaffected | as expected | pass | `test_scan_threshold_blocks_source_and_exempts_network`; `test_scan_active_blocks_are_not_evicted_by_new_sources` |
| SR-1 | normal | standard library runtime | import package | no runtime third-party dependency | as expected | pass | package imports across suite |
| SR-2 | normal | offline/live parser parity | malformed packet in both modes | DROP | offline and callback paths covered | pass | `test_total_length_larger_than_capture_is_truncated`; `test_malformed_packet_is_dropped_and_logged` |
| SR-3 | adversarial | multi-queue shared state | INPUT/OUTPUT replies | shared ESTABLISHED state | state shared in Firewall; queue-binding interaction not covered | partial | `test_accepted_flow_creates_state_and_reply_is_established` |
| SR-4 | adversarial | NFQUEUE rules have no bypass | example setup scripts | process death stops queued traffic | scripts added; namespace test not covered | partial | not covered |
| SR-5 | normal | undeclared-chain fallback warning | missing chain declaration | startup warning | fallback policy parsing covered; startup warning not covered | partial | `test_undeclared_chain_falls_back_to_accept` |
| SR-6 | recovery | stop/restart live queue | kill then restart process | traffic stops then resumes | live test skipped | gap | `test_live_nfqueue_accepts_traffic` (skipped) |
