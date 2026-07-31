use rpkv2::{
    blockstore::Blockstore,
    config::ProductionConfig,
    identity_keys::{generate_validator_identity, hex},
    ledger::TransactionBatch,
};
use std::{fs, path::Path};

#[path = "common/temp_dir.rs"]
mod test_temp;
use test_temp::temp_dir;

fn config_text(key_path: &Path, spki_path: &Path, verify_key_hex: &str) -> String {
    format!(
        r#"
format_version = 999

[local]
bind_address = "127.0.0.1:4433"
validator_id = "validator-a"
private_key_path = '{}'

[[peers]]
validator_id = "validator-b"
spki_pin_path = '{}'
ed25519_verify_key_hex = "{}"

[replay]
slot_window = 1024

[queues]
raw = 8
deduped = 8
verified = 8
packed = 8
bank = 8
poh = 8
shred = 8
signed = 8

[rate_limits]
packets_per_second = 1
bytes_per_second = 1

[storage]
directory = "store"
allow_unsafe_demo_storage = true

[metrics]
bind_address = "127.0.0.1:9100"
"#,
        key_path.display(),
        spki_path.display(),
        verify_key_hex
    )
}

#[test]
fn incompatible_config_format_version_is_rejected() {
    let dir = temp_dir("upgrade-compatibility");
    let local = generate_validator_identity("validator-a", dir.join("local"), false).unwrap();
    let peer = generate_validator_identity("validator-b", dir.join("peer"), false).unwrap();
    let cfg = toml::from_str::<ProductionConfig>(&config_text(
        &local.transport_private_key_path,
        &peer.transport_public_spki_path,
        &peer.public_identity.packet_verify_key_hex,
    ))
    .unwrap();

    assert!(cfg.validate().is_err());
}

#[test]
fn incompatible_ledger_object_version_is_rejected() {
    let batch = TransactionBatch::new(0, vec![b"tx".to_vec()]).unwrap();
    let mut encoded = batch.encode().unwrap();
    encoded[4] = 99;

    assert!(TransactionBatch::decode(&encoded).is_err());
}

#[test]
fn incompatible_blockstore_record_version_is_rejected() {
    let dir = temp_dir("upgrade-compatibility");
    let log = dir.join("blockstore.log");
    let mut record = Vec::new();
    record.extend_from_slice(b"RPBS");
    record.push(99);
    record.push(1);
    record.extend_from_slice(&0u32.to_be_bytes());
    record.extend_from_slice(&[0u8; 32]);
    fs::write(log, record).unwrap();

    assert!(Blockstore::open(&dir).is_err());
}

#[test]
fn compatibility_constants_are_stable_for_current_release() {
    assert_eq!(rpkv2::config::PRODUCTION_CONFIG_VERSION, 1);
    assert_eq!(rpkv2::fastpath::packet::PACKET_VERSION, 1);
    assert_eq!(rpkv2::ledger::LEDGER_VERSION, 1);
    assert_eq!(rpkv2::snapshot::SNAPSHOT_VERSION, 1);
    assert_eq!(rpkv2::transaction::TRANSACTION_VERSION, 1);
    assert_eq!(rpkv2::consensus_messages::CONSENSUS_MESSAGE_VERSION, 1);
    assert_eq!(rpkv2::blockstore::BLOCKSTORE_RECORD_VERSION, 1);
    assert_eq!(rpkv2::tiles::storage::STORAGE_RECORD_VERSION, 1);
    assert_eq!(hex(&[0xab, 0xcd]), "abcd");
}
