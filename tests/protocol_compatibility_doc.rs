use std::fs;

#[test]
fn protocol_compatibility_doc_defines_target_surfaces_and_tests() {
    let text = fs::read_to_string("docs/protocol-compatibility.md").unwrap();
    for required in [
        "custom rpkv2 validator network",
        "not currently Solana/Agave-compatible",
        "Firedancer-compatible",
        "Frankendancer-compatible",
        "Transaction ingress",
        "Gossip",
        "Repair",
        "Block/shred propagation",
        "Vote propagation",
        "Snapshot distribution",
        "RPC",
        "Supported",
        "Unsupported",
        "Future work",
        "Golden fixtures",
        "unknown versions",
        "negative compatibility tests",
        "Interop tests",
    ] {
        assert!(
            text.contains(required),
            "missing protocol compatibility item: {required}"
        );
    }
}
