use std::fs;

#[test]
fn conformance_doc_mentions_versioned_release_blocking_fixtures() {
    let text = fs::read_to_string("docs/conformance-suite.md").unwrap();
    for required in [
        "tests/fixtures/conformance/v1/",
        "fixture version",
        "compatibility target",
        "Compatibility failures are release blocking",
        "cargo test",
        "genesis/config",
        "public validator identities",
        "transactions",
        "blocks",
        "votes",
        "shreds",
        "snapshots",
        "foreign or malformed protocol bytes",
    ] {
        assert!(
            text.contains(required),
            "missing conformance doc item: {required}"
        );
    }
}
