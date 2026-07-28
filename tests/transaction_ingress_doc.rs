use std::fs;

#[test]
fn transaction_ingress_doc_mentions_interfaces_validation_and_limits() {
    let text = fs::read_to_string("docs/transaction-ingress.md").unwrap();
    for required in [
        "QUIC",
        "UDP",
        "RPC",
        "Local",
        "TRANSACTION_VERSION = 1",
        "required signatures verify",
        "source rate limits",
        "rate_limited:<reason>",
        "malformed:<reason>",
        "invalid:<reason>",
        "No Solana-compatible RPC surface exists",
        "ingress replay cache is in memory",
    ] {
        assert!(
            text.contains(required),
            "missing transaction ingress doc item: {required}"
        );
    }
}
