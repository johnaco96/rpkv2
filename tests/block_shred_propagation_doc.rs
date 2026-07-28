use std::fs;

#[test]
fn block_shred_propagation_doc_mentions_messages_transports_and_metrics() {
    let text = fs::read_to_string("docs/block-shred-propagation.md").unwrap();
    for required in [
        "QUIC datagrams",
        "UDP packets",
        "streams",
        "BlockPropagation",
        "ShredPropagation",
        "RepairRequest",
        "RepairResponse",
        "producer is leader",
        "shred integrity",
        "invalid signatures",
        "invalid leaders",
        "corrupt shreds",
        "missing repair data",
        "Erasure coding is not implemented",
    ] {
        assert!(
            text.contains(required),
            "missing block/shred propagation doc item: {required}"
        );
    }
}
