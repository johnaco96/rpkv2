use std::fs;

#[test]
fn monitoring_contract_mentions_required_alerts_and_metrics() {
    let text = fs::read_to_string("docs/validator-monitoring.md").unwrap();
    for required in [
        "Node not ready",
        "No recent slot progress",
        "High replay drops",
        "High bad signatures",
        "Queue saturation",
        "Blockstore write errors",
        "Fork divergence",
        "Consensus vote failures",
        "Snapshot failure",
        "Disk space low",
        "rpkv2_replay_drops_total",
        "rpkv2_bad_signatures_total",
        "rpkv2_queue_full_total",
        "rpkv2_storage_errors_total",
        "rpkv2_non_leader_production_rejections_total",
        "rpkv2_latest_slot",
        "rpkv2_consensus_vote_failures_total",
        "rpkv2_snapshot_failures_total",
        "rpkv2_disk_available_bytes",
    ] {
        assert!(
            text.contains(required),
            "missing monitoring contract item: {required}"
        );
    }
}
