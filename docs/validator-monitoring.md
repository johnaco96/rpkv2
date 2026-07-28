# Validator Monitoring Contract

Ticket 14.3 defines the minimum dashboard and alert contract for operating an
rpkv2 validator node. This document maps alerts to metrics that exist today and
calls out missing metrics that must be added before a production readiness claim.

Metrics are exposed in Prometheus text format at the configured metrics address.
Health and readiness are available at `/health`, `/ready`, and `/readyz`.

## Dashboard Panels

| Panel | Metrics |
| --- | --- |
| Readiness | `/ready` HTTP status, `/health` JSON `ready`, `state`, and checks |
| Traffic | `rate(rpkv2_packets_received_total[5m])`, `rate(rpkv2_packets_accepted_total[5m])` |
| Packet rejection | `rate(rpkv2_malformed_packets_total[5m])`, `rate(rpkv2_replay_drops_total[5m])`, `rate(rpkv2_stale_slot_drops_total[5m])`, `rate(rpkv2_bad_signatures_total[5m])`, `rate(rpkv2_unknown_peer_drops_total[5m])` |
| Queue pressure | `rpkv2_queue_depth{tile="..."}`, `rate(rpkv2_queue_full_total{stage="..."}[5m])`, `rate(rpkv2_queue_dropped_total{stage="..."}[5m])` |
| Verification | `rpkv2_verification_batch_size_*`, `rpkv2_verification_latency_us_*` |
| End-to-end latency | `rpkv2_packet_latency_us_*` |
| Storage | `rate(rpkv2_shreds_written_total[5m])`, `rate(rpkv2_storage_errors_total[5m])` |
| Connections | `rpkv2_active_connections` |
| Per-peer abuse | `rpkv2_peer_malformed_total{peer="..."}`, `rpkv2_peer_invalid_signatures_total{peer="..."}`, `rpkv2_peer_replays_total{peer="..."}`, `rpkv2_peer_throttled_total{peer="..."}` |
| Execution | `rate(rpkv2_execution_batches_total[5m])`, `rate(rpkv2_execution_transactions_total[5m])`, `rate(rpkv2_execution_conflicts_total[5m])` |
| Leader/fork safety proxy | `rate(rpkv2_non_leader_production_rejections_total[5m])` |

## Alerts

| Alert | Expression | Recommended Threshold | Operator Action |
| --- | --- | --- | --- |
| Node not ready | `/ready` returns non-200, or `/health` JSON `ready=false` | Critical after 60 seconds; warning after 15 seconds | Check startup logs, config validation, key loading, socket bind, storage writability, metrics endpoint, and tile health. Do not send production traffic until ready is restored. |
| No recent slot progress | Required metric not yet implemented: `rpkv2_latest_slot` or `rpkv2_latest_finalized_slot` | Critical if no increase for 2 slot windows or 60 seconds, whichever is longer | Inspect consensus/fork-choice logs, peer connectivity, leader schedule, blockstore writes, and replay status. This is a blocking observability gap today. |
| High replay drops | `rate(rpkv2_replay_drops_total[5m])` or `rate(rpkv2_peer_replays_total{peer!="unknown"}[5m])` | Warning above 1% of received packets for 5 minutes; critical above 5% | Identify source peers, confirm slot window and clocks, check for replay storm, throttle or revoke abusive peers if needed. |
| High bad signatures | `rate(rpkv2_bad_signatures_total[5m])` or `rate(rpkv2_peer_invalid_signatures_total[5m])` | Warning above 0.1% of received packets for 5 minutes; critical above 1% | Identify peer labels, verify key rotation state, check packet signing key registry, throttle or disconnect peer, consider revocation if malicious. |
| Queue saturation | `rpkv2_queue_depth{tile="..."}` near configured queue size, or `rate(rpkv2_queue_full_total{stage="..."}[5m]) > 0`, or `rate(rpkv2_queue_dropped_total{stage="..."}[5m]) > 0` | Warning at 75% sustained depth for 5 minutes; critical at 90% for 1 minute or any production queue drops | Reduce offered load, inspect slow downstream tile, check CPU/storage saturation, scale node resources, or adjust queue policy only after root cause is known. |
| Blockstore write errors | `rate(rpkv2_storage_errors_total[5m]) > 0` | Critical on any increase in production | Stop accepting traffic if errors continue, inspect disk, permissions, corruption reports, and storage recovery policy. Preserve files for audit before repair. |
| Fork divergence | Direct metric not yet implemented. Current proxy: `rate(rpkv2_non_leader_production_rejections_total[5m])`, execution conflicts, fork-choice logs | Warning on any sustained non-leader production rejection; critical if canonical fork changes repeatedly or finality stalls | Inspect leader schedule, validator set consistency, vote messages, fork-choice traces, and peer set. Add direct metrics before production: fork count, best fork hash, finalized root, reorg count. |
| Consensus vote failures | Direct metric not yet implemented. Current proxy: consensus validation errors in logs and `rpkv2_non_leader_production_rejections_total` for proposal authorization | Warning on repeated vote validation errors; critical if votes stop or equivocation appears | Check consensus voting keys, validator authorization, slot skew, lockout safety, and equivocation evidence. Add `rpkv2_consensus_vote_failures_total{reason="..."}` before production. |
| Snapshot failure | Direct metric not yet implemented. Current signal is `nodectl snapshot`/`restore-snapshot` exit code and logs | Critical on any failed restore of an operator-selected snapshot; warning on snapshot creation/copy failure | Do not restore unvalidated snapshots. Check snapshot hash/signature, disk path, validator set, consensus safety state, and source provenance. Add `rpkv2_snapshot_failures_total{operation="..."}` before production. |
| Disk space low | Host metric required: `node_filesystem_avail_bytes` or platform equivalent for storage directory filesystem | Warning below 20% free or less than 100 GiB; critical below 10% free or less than 25 GiB | Stop or reduce ingest, expand disk, archive old data only according to retention policy, and never delete data needed for replay, fork choice, repair, or audit. |

## Existing Metric Mapping

These alert inputs exist today:

- `rpkv2_packets_received_total`
- `rpkv2_packets_accepted_total`
- `rpkv2_malformed_packets_total`
- `rpkv2_replay_drops_total`
- `rpkv2_stale_slot_drops_total`
- `rpkv2_bad_signatures_total`
- `rpkv2_unknown_peer_drops_total`
- `rpkv2_shreds_written_total`
- `rpkv2_storage_errors_total`
- `rpkv2_active_connections`
- `rpkv2_non_leader_production_rejections_total`
- `rpkv2_execution_batches_total`
- `rpkv2_execution_transactions_total`
- `rpkv2_execution_conflicts_total`
- `rpkv2_verification_batch_size_count`
- `rpkv2_verification_batch_size_sum`
- `rpkv2_verification_batch_size_max`
- `rpkv2_verification_latency_us_count`
- `rpkv2_verification_latency_us_sum`
- `rpkv2_verification_latency_us_max`
- `rpkv2_packet_latency_us_count`
- `rpkv2_packet_latency_us_sum`
- `rpkv2_packet_latency_us_max`
- `rpkv2_queue_depth{tile="..."}`
- `rpkv2_queue_full_total{stage="...",policy="..."}`
- `rpkv2_queue_dropped_total{stage="...",policy="..."}`
- `rpkv2_queue_accepted_after_spin_total{stage="...",policy="..."}`
- `rpkv2_peer_packets_total{peer="..."}`
- `rpkv2_peer_bytes_total{peer="..."}`
- `rpkv2_peer_malformed_total{peer="..."}`
- `rpkv2_peer_invalid_signatures_total{peer="..."}`
- `rpkv2_peer_replays_total{peer="..."}`
- `rpkv2_peer_throttled_total{peer="..."}`

## Required Metrics Before Production

These metrics are required for a production monitoring contract but are not yet
implemented:

- `rpkv2_latest_slot`
- `rpkv2_latest_finalized_slot`
- `rpkv2_fork_count`
- `rpkv2_reorgs_total`
- `rpkv2_finalized_root_changes_total`
- `rpkv2_consensus_vote_failures_total{reason="..."}`
- `rpkv2_snapshot_failures_total{operation="..."}`
- `rpkv2_disk_available_bytes{path="..."}`
- `rpkv2_disk_total_bytes{path="..."}`

Until these exist, operations must combine rpkv2 metrics with host monitoring,
logs, and `nodectl` exit codes.

## Simulated Alert Checks

Feasible local simulations today:

- Bad config before start: `cargo run --bin nodectl -- validate-config --config bad.toml` must exit nonzero.
- Queue saturation: run the overload suite and confirm `rpkv2_queue_full_total` and `rpkv2_queue_dropped_total` increase for the stressed stage.
- Bad signatures: run invalid-signature overload scenario and confirm `rpkv2_peer_invalid_signatures_total` and `rpkv2_bad_signatures_total` increase.
- Replay storm: run replay overload scenario and confirm `rpkv2_peer_replays_total` and `rpkv2_replay_drops_total` increase.
- Storage recovery: corrupt/truncate a demo storage file in a test directory and run `nodectl repair-ledger`.

## Review Cadence

Review this contract whenever a new validator subsystem adds a failure mode.
Every production-critical rejection path should have:

- a metric;
- a bounded label set;
- an alert threshold;
- an operator action;
- a test or documented simulation path.
