use std::fs;

#[test]
fn upgrade_runbook_mentions_compatibility_backup_and_rollback_requirements() {
    let text = fs::read_to_string("docs/safe-upgrade-rollback.md").unwrap();
    for required in [
        "Packet wire protocol",
        "Consensus message wire protocol",
        "Transaction format",
        "Ledger format",
        "Snapshot format",
        "Production config format",
        "Blockstore record format",
        "Demo shred storage format",
        "Database schema",
        "Required Backups",
        "Rollback Dry Run",
        "Rollback Procedure",
        "unsupported config `format_version` fails validation",
        "There are no database schema migrations in this release",
    ] {
        assert!(
            text.contains(required),
            "missing upgrade runbook item: {required}"
        );
    }
}
