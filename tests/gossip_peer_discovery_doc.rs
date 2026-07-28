use std::fs;

#[test]
fn gossip_doc_mentions_security_and_operational_contract() {
    let text = fs::read_to_string("docs/gossip-peer-discovery.md").unwrap();
    for required in [
        "static bootstrap peers",
        "signed `PeerAnnouncement`",
        "validator set",
        "consensus voting key",
        "expiration time",
        "sequence number",
        "Rejected messages are metered",
        "Network transport",
        "future work",
    ] {
        assert!(
            text.contains(required),
            "missing gossip doc item: {required}"
        );
    }
}
